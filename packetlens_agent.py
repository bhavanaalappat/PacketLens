#!/usr/bin/env python3
import argparse
import json
import os
import socket
import struct
import time
import urllib.request


ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = {0x8100, 0x88A8}

PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}

PROTO_TABLES = [
    ("/proc/net/tcp", 6, False),
    ("/proc/net/tcp6", 6, True),
    ("/proc/net/udp", 17, False),
    ("/proc/net/udp6", 17, True),
]


def proc_ipv4(hex_ip):
    raw = int(hex_ip, 16).to_bytes(4, "little")
    return socket.inet_ntop(socket.AF_INET, raw)


def proc_ipv6(hex_ip):
    raw = bytes.fromhex(hex_ip)
    fixed = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, fixed)


def split_proc_endpoint(value, ipv6):
    ip_hex, port_hex = value.split(":", 1)
    ip = proc_ipv6(ip_hex) if ipv6 else proc_ipv4(ip_hex)
    return ip, int(port_hex, 16)


def read_process_name(pid):
    for name in ("comm", "cmdline"):
        try:
            with open(f"/proc/{pid}/{name}", "rb") as f:
                raw = f.read(512)
        except OSError:
            continue
        if not raw:
            continue
        value = raw.split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()
        if value:
            return os.path.basename(value)
    return ""


def build_inode_process_map():
    result = {}
    try:
        pids = list(filter(str.isdigit, os.listdir("/proc")))
    except OSError:
        return result

    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue

        proc_name = ""
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if not (target.startswith("socket:[") and target.endswith("]")):
                continue
            inode = target[8:-1]
            if not proc_name:
                proc_name = read_process_name(pid)
            if proc_name:
                result[inode] = proc_name
    return result


def build_socket_process_map():
    inode_processes = build_inode_process_map()
    result = {}

    for path, proto, ipv6 in PROTO_TABLES:
        try:
            with open(path, "r", encoding="utf-8") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    local_ip, local_port = split_proc_endpoint(parts[1], ipv6)
                    remote_ip, remote_port = split_proc_endpoint(parts[2], ipv6)
                    inode = parts[9]
                    proc = inode_processes.get(inode, "")
                    if not proc:
                        continue

                    result[(local_ip, local_port, remote_ip, remote_port, proto)] = proc
                    result[(remote_ip, remote_port, local_ip, local_port, proto)] = proc
                    result[("__local_port__", local_port, proto)] = proc

                    if remote_ip in {"0.0.0.0", "::"} and remote_port == 0:
                        result[(local_ip, local_port, "", 0, proto)] = proc
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return result


def resolve_process(flow, socket_processes):
    exact = socket_processes.get((
        flow["src_ip"], flow["src_port"], flow["dst_ip"], flow["dst_port"], flow["proto_num"]
    ))
    if exact:
        return exact

    reverse = socket_processes.get((
        flow["dst_ip"], flow["dst_port"], flow["src_ip"], flow["src_port"], flow["proto_num"]
    ))
    if reverse:
        return reverse

    src_listen = socket_processes.get((flow["src_ip"], flow["src_port"], "", 0, flow["proto_num"]))
    if src_listen:
        return src_listen

    dst_listen = socket_processes.get((flow["dst_ip"], flow["dst_port"], "", 0, flow["proto_num"]))
    if dst_listen:
        return dst_listen

    src_port_proc = socket_processes.get(("__local_port__", flow["src_port"], flow["proto_num"]))
    if src_port_proc:
        return src_port_proc

    dst_port_proc = socket_processes.get(("__local_port__", flow["dst_port"], flow["proto_num"]))
    if dst_port_proc:
        return dst_port_proc

    return flow.get("process", "")


def tcp_state_from_flags(flags):
    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)
    fin = bool(flags & 0x01)
    rst = bool(flags & 0x04)
    if fin or rst:
        return "FIN-WAIT"
    if syn and not ack:
        return "SYN-SENT"
    if ack:
        return "EST"
    return "NEW"


def parse_packet(packet):
    if len(packet) < 14:
        return None

    offset = 14
    eth_type = struct.unpack("!H", packet[12:14])[0]
    while eth_type in ETH_P_VLAN:
        if len(packet) < offset + 4:
            return None
        eth_type = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
        offset += 4

    if eth_type == ETH_P_IP:
        return parse_ipv4(packet, offset)
    if eth_type == ETH_P_IPV6:
        return parse_ipv6(packet, offset)
    return None


def parse_ipv4(packet, offset):
    if len(packet) < offset + 20:
        return None
    first = packet[offset]
    ihl = (first & 0x0F) * 4
    if ihl < 20 or len(packet) < offset + ihl:
        return None

    proto = packet[offset + 9]
    if proto not in PROTO_NAMES:
        return None

    src_ip = socket.inet_ntop(socket.AF_INET, packet[offset + 12:offset + 16])
    dst_ip = socket.inet_ntop(socket.AF_INET, packet[offset + 16:offset + 20])
    l4 = offset + ihl

    return parse_l4(packet, l4, src_ip, dst_ip, proto)


def parse_ipv6(packet, offset):
    if len(packet) < offset + 40:
        return None

    proto = packet[offset + 6]
    if proto not in PROTO_NAMES:
        return None

    src_ip = socket.inet_ntop(socket.AF_INET6, packet[offset + 8:offset + 24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, packet[offset + 24:offset + 40])
    l4 = offset + 40

    return parse_l4(packet, l4, src_ip, dst_ip, proto)


def parse_l4(packet, offset, src_ip, dst_ip, proto):
    src_port = 0
    dst_port = 0
    state = "EST"

    if proto in (6, 17):
        if len(packet) < offset + 4:
            return None
        src_port, dst_port = struct.unpack("!HH", packet[offset:offset + 4])
        if proto == 6:
            if len(packet) < offset + 14:
                return None
            state = tcp_state_from_flags(packet[offset + 13])
    elif proto == 1:
        state = "EST"
    elif proto == 2:
        state = "EST"
    elif proto == 58:
        state = "EST"

    return {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto_num": proto,
        "protocol": PROTO_NAMES[proto],
        "state": state,
    }


def flow_key(flow):
    a = (flow["src_ip"], flow["src_port"])
    b = (flow["dst_ip"], flow["dst_port"])
    if a <= b:
        return (a[0], a[1], b[0], b[1], flow["proto_num"])
    return (b[0], b[1], a[0], a[1], flow["proto_num"])


def update_flow(flows, parsed, packet_len):
    key = flow_key(parsed)
    now = time.monotonic()
    flow = flows.get(key)
    if flow is None:
        flow = {
            "src_ip": key[0],
            "src_port": key[1],
            "dst_ip": key[2],
            "dst_port": key[3],
            "proto_num": key[4],
            "protocol": PROTO_NAMES[key[4]],
            "packets": 0,
            "bytes": 0,
            "process": "",
            "state": parsed["state"],
            "last_seen": now,
        }
        flows[key] = flow

    flow["packets"] += 1
    flow["bytes"] += packet_len
    flow["last_seen"] = now
    if parsed["state"] in {"FIN-WAIT", "SYN-SENT"} or flow["state"] in {"NEW", "SYN-SENT"}:
        flow["state"] = parsed["state"]
    elif parsed["state"] == "EST":
        flow["state"] = "EST"


def cleanup_flows(flows, max_age):
    now = time.monotonic()
    stale = [key for key, flow in flows.items() if now - flow["last_seen"] > max_age]
    for key in stale:
        del flows[key]


def snapshot_flows(host, flows, socket_processes):
    out = []
    for flow in flows.values():
        proc = resolve_process(flow, socket_processes)
        if proc:
            flow["process"] = proc
        out.append({
            "host": host,
            "src_ip": flow["src_ip"],
            "src_port": flow["src_port"],
            "dst_ip": flow["dst_ip"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
            "packets": flow["packets"],
            "bytes": flow["bytes"],
            "process": flow.get("process", ""),
            "state": flow["state"],
        })
    return out


def post(server, host, flows):
    body = json.dumps({"host": host, "flows": flows}).encode("utf-8")
    req = urllib.request.Request(
        server.rstrip("/") + "/ingest",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode("utf-8", errors="replace")


def default_interface():
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except OSError:
        pass
    return "eth0"


def main():
    parser = argparse.ArgumentParser(description="PacketLens remote packet-capture agent")
    parser.add_argument("--server", required=True, help="PacketLens API base URL, e.g. http://10.0.0.5:8765")
    parser.add_argument("--host", default=socket.gethostname(), help="Host label shown in PacketLens")
    parser.add_argument("--interface", default=default_interface(), help="Interface to capture, default: route interface")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between reports")
    parser.add_argument("--flow-timeout", type=float, default=120.0, help="Seconds to keep idle captured flows")
    args = parser.parse_args()

    flows = {}
    socket_processes = {}
    next_post = time.monotonic() + args.interval
    next_proc_refresh = 0.0

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((args.interface, 0))
    sock.settimeout(0.25)

    print(f"capturing on {args.interface}, sending to {args.server} as {args.host}", flush=True)

    while True:
        now = time.monotonic()
        if now >= next_proc_refresh:
            socket_processes = build_socket_process_map()
            next_proc_refresh = now + 1.0

        try:
            packet, _addr = sock.recvfrom(65535)
        except socket.timeout:
            packet = None

        if packet:
            parsed = parse_packet(packet)
            if parsed:
                update_flow(flows, parsed, len(packet))

        now = time.monotonic()
        if now >= next_post:
            cleanup_flows(flows, args.flow_timeout)
            snapshot = snapshot_flows(args.host, flows, socket_processes)
            try:
                post(args.server, args.host, snapshot)
                print(f"sent {len(snapshot)} captured flows to {args.server}", flush=True)
            except Exception as exc:
                print(f"send failed: {exc}", flush=True)
            next_post = now + args.interval


if __name__ == "__main__":
    main()
