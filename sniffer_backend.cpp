// sniffer_backend.cpp  (updated — adds HTTP API)
#include "sniffer_backend.h"
#include "tcp_parser.h"

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <fstream>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <chrono>
#include <limits.h>
#include <unistd.h>
#include <vector>

// ── Internal packet queue ─────────────────────────────────────────────────────
struct SnifferBackend::RawPacket {
    pcap_pkthdr           header;
    std::vector<u_char>   data;
};

struct SnifferBackend::PacketQueue {
    std::queue<RawPacket>      q;
    std::mutex                 mtx;
    std::condition_variable    cv;
    bool                       done = false;

    void push(RawPacket rp) {
        std::unique_lock<std::mutex> lk(mtx);
        q.push(std::move(rp));
        cv.notify_one();
    }

    bool pop(RawPacket& out) {
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait(lk, [&]{ return !q.empty() || done; });
        if (q.empty()) return false;
        out = std::move(q.front());
        q.pop();
        return true;
    }

    void shutdown() {
        std::unique_lock<std::mutex> lk(mtx);
        done = true;
        cv.notify_all();
    }
};

// ── TCP flag helper ───────────────────────────────────────────────────────────
struct TCPFlags { 
    bool syn = false;  // 0x02 - Synchronize
    bool ack = false;  // 0x10 - Acknowledgment
    bool fin = false;  // 0x01 - Final
    bool rst = false;  // 0x04 - Reset
};

static TCPFlags parse_tcp_flags(const u_char* tcp_hdr) {
    uint8_t f = tcp_hdr[13];  // Flags byte
    return { 
        bool(f & 0x02),  // SYN
        bool(f & 0x10),  // ACK
        bool(f & 0x01),  // FIN
        bool(f & 0x04)   // RST
    };
}

// ── Process name helper ───────────────────────────────────────────────────────
static std::string read_process_name(pid_t pid) {
    std::string p;
    std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
    if (f && std::getline(f, p)) {
        while (!p.empty() && (p.back() == '\n' || p.back() == '\r')) p.pop_back();
        if (!p.empty()) return p;
    }
    std::ifstream g("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    if (g) {
        std::string c; std::getline(g, c, '\0');
        if (!c.empty()) {
            auto pos = c.find_last_of('/');
            return (pos != std::string::npos) ? c.substr(pos + 1) : c;
        }
    }

    char exe[PATH_MAX];
    std::string exe_path = "/proc/" + std::to_string(pid) + "/exe";
    ssize_t n = readlink(exe_path.c_str(), exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
        std::string path(exe);
        auto pos = path.find_last_of('/');
        return (pos != std::string::npos) ? path.substr(pos + 1) : path;
    }

    std::ifstream s("/proc/" + std::to_string(pid) + "/status");
    std::string line;
    while (std::getline(s, line)) {
        if (line.rfind("Name:", 0) == 0) {
            auto start = line.find_first_not_of(" \t", 5);
            if (start != std::string::npos) return line.substr(start);
        }
    }
    return {};
}

// ── Constructor / Destructor ──────────────────────────────────────────────────
SnifferBackend::SnifferBackend(QObject* parent)
    : QObject(parent), queue_(std::make_unique<PacketQueue>())
{}

SnifferBackend::~SnifferBackend() {
    stop();
}

std::vector<SnifferBackend::CaptureInterface>
SnifferBackend::availableInterfaces(QString* error) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    std::vector<CaptureInterface> out;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
        if (error) *error = QString("No devices found: %1\nRun as root.").arg(errbuf);
        return out;
    }

    for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
        if (!dev->name) continue;
        CaptureInterface iface;
        iface.name = QString::fromUtf8(dev->name);
        iface.description = dev->description
            ? QString::fromUtf8(dev->description)
            : QString();
        out.push_back(std::move(iface));
    }

    pcap_freealldevs(alldevs);
    return out;
}

// ── start() ───────────────────────────────────────────────────────────────────
bool SnifferBackend::start(const QStringList& interfaces) {
    if (running_.load()) {
        stop();
    }

    QStringList selected = interfaces;
    if (selected.isEmpty()) {
        QString iface_error;
        auto available = availableInterfaces(&iface_error);
        if (available.empty()) {
            emit errorOccurred(iface_error.isEmpty()
                ? QString("No capture interfaces found.\nRun as root.")
                : iface_error);
            return false;
        }
        selected << available.front().name;
    }

    queue_ = std::make_unique<PacketQueue>();
    manager_.clear();

    char errbuf[PCAP_ERRBUF_SIZE];
    std::vector<pcap_t*> opened;
    for (const auto& iface : selected) {
        pcap_t* handle = pcap_open_live(iface.toUtf8().constData(), BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            for (pcap_t* h : opened) pcap_close(h);
            emit errorOccurred(QString("pcap_open_live failed for %1: %2").arg(iface, errbuf));
            return false;
        }

        if (pcap_datalink(handle) != DLT_EN10MB) {
            pcap_close(handle);
            for (pcap_t* h : opened) pcap_close(h);
            emit errorOccurred(QString("Unsupported link-layer type on %1 (need Ethernet).").arg(iface));
            return false;
        }

        struct bpf_program fp;
        // Capture TCP, UDP (IPv4 & IPv6), ICMP, ICMPv6, and IGMP
        char filter[] = "tcp or udp or icmp or igmp or ip6 or icmp6";
        if (pcap_compile(handle, &fp, filter, 1, 0) == -1) {
            QString msg = QString("Failed to compile/set BPF filter on %1: %2")
                              .arg(iface, pcap_geterr(handle));
            pcap_close(handle);
            for (pcap_t* h : opened) pcap_close(h);
            emit errorOccurred(msg);
            return false;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            QString msg = QString("Failed to compile/set BPF filter on %1: %2")
                              .arg(iface, pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            for (pcap_t* h : opened) pcap_close(h);
            emit errorOccurred(msg);
            return false;
        }
        pcap_freecode(&fp);
        opened.push_back(handle);
    }

    if (opened.empty()) {
        emit errorOccurred("No capture interfaces selected.");
        return false;
    }

    pcap_handles_.reserve(opened.size());
    for (pcap_t* handle : opened) {
        pcap_handles_.push_back(handle);
    }
    running_.store(true);

    sniffer_threads_.reserve(pcap_handles_.size());
    for (void* handle : pcap_handles_) {
        sniffer_threads_.emplace_back(&SnifferBackend::snifferThread, this, handle);
    }
    worker_thread_  = std::thread(&SnifferBackend::workerThread,  this);
    cleanup_thread_ = std::thread(&SnifferBackend::cleanupThread, this);  // Start active cleanup

    // ── Start embedded HTTP API ───────────────────────────────────────────────
    httpApi_ = std::make_unique<HttpApi>(
        HTTP_API_PORT,
        // Snapshot lambda — called from HttpApi's thread; FlowManager is mutex-guarded
        [this]() -> std::vector<FlowSnapshot> {
            return manager_.get_snapshot();
        },
        // Stats lambda
        [this](uint64_t& pkts, uint64_t& bytes, size_t& flows) {
            pkts  = manager_.total_packets();
            bytes = manager_.total_bytes();
            flows = manager_.get_flow_count();
        },
        // Remote agent ingest lambda
        [this](const std::vector<FlowSnapshot>& flows) {
            for (const auto& flow : flows) {
                manager_.ingest_remote_snapshot(flow);
            }
        }
    );

    if (!httpApi_->start()) {
        // Non-fatal — PacketLens works fine without the API
        std::cerr << "[HttpApi] Failed to start — MCP integration unavailable\n";
        httpApi_.reset();
    }

    return true;
}

// ── stop() ────────────────────────────────────────────────────────────────────
void SnifferBackend::stop() {
    if (!running_.exchange(false)) return;

    if (httpApi_) {
        httpApi_->stop();
        httpApi_.reset();
    }

    for (void* handle : pcap_handles_) {
        pcap_breakloop(static_cast<pcap_t*>(handle));
    }
    queue_->shutdown();

    for (auto& thread : sniffer_threads_) {
        if (thread.joinable()) thread.join();
    }
    sniffer_threads_.clear();
    if (worker_thread_.joinable())  worker_thread_.join();
    if (cleanup_thread_.joinable()) cleanup_thread_.join();

    for (void* handle : pcap_handles_) {
        pcap_close(static_cast<pcap_t*>(handle));
    }
    pcap_handles_.clear();
}

// ── Sniffer thread ────────────────────────────────────────────────────────────
void SnifferBackend::snifferThread(void* raw_handle) {
    auto* handle = static_cast<pcap_t*>(raw_handle);
    while (running_.load()) {
        pcap_pkthdr* hdr;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if (res <= 0) continue;

        RawPacket rp;
        rp.header = *hdr;
        rp.data.assign(pkt, pkt + hdr->caplen);
        queue_->push(std::move(rp));
    }
}

// ── Worker thread (handles IPv4, IPv6, TCP, UDP, ICMP, IGMP, ICMPv6) ────────
void SnifferBackend::workerThread() {
    TcpParser parser;
    std::unordered_map<FlowKey, std::chrono::steady_clock::time_point, FlowHash> last_lookup;
    static constexpr size_t MAX_LOOKUP_RETRY_TRACKING = 12000;
    static constexpr int LOOKUP_RETRY_MAX_AGE_SEC = 15;

    RawPacket rp;
    while (queue_->pop(rp)) {
        if (rp.header.caplen < 14) continue;

        const u_char* pkt = rp.data.data();
        uint16_t eth_type = ntohs(*reinterpret_cast<const uint16_t*>(pkt + 12));
        
        FlowKey key;
        uint32_t packet_bytes = rp.header.len;
        bool tcp_syn = false, tcp_ack = false, tcp_fin = false, tcp_rst = false;
        bool is_tcp_udp = false;
        std::string proto_name;
        std::string packet_src_ip;
        std::string packet_dst_ip;
        uint16_t packet_src_port = 0;
        uint16_t packet_dst_port = 0;

        // ── IPv4 packets ──────────────────────────────────────────────────────
        if (eth_type == 0x0800) {
            if (rp.header.caplen < 14 + 20) continue;

            const u_char* ip  = pkt + 14;
            uint8_t ihl       = (ip[0] & 0x0F) * 4;
            uint8_t proto     = ip[9];
            
            if (rp.header.caplen < static_cast<uint32_t>(14 + ihl + 4)) continue;

            uint32_t sip = 0, dip = 0;
            std::memcpy(&sip, ip + 12, 4);
            std::memcpy(&dip, ip + 16, 4);
            packet_src_ip = ipv4_to_string(sip);
            packet_dst_ip = ipv4_to_string(dip);

            const u_char* l4 = ip + ihl;
            uint16_t sport = 0, dport = 0;

            // TCP and UDP have ports
            if (proto == 6 || proto == 17) {
                if (rp.header.caplen < static_cast<uint32_t>(14 + ihl + 4)) continue;
                sport = ntohs(*reinterpret_cast<const uint16_t*>(l4));
                dport = ntohs(*reinterpret_cast<const uint16_t*>(l4 + 2));
                packet_src_port = sport;
                packet_dst_port = dport;
                is_tcp_udp = true;

                if (proto == 6) {
                    if (rp.header.caplen >= static_cast<uint32_t>(14 + ihl + 14)) {
                        auto fl = parse_tcp_flags(l4);
                        tcp_syn = fl.syn;
                        tcp_ack = fl.ack;
                        tcp_fin = fl.fin;
                        tcp_rst = fl.rst;
                    }
                    proto_name = "TCP";
                } else {
                    proto_name = "UDP";
                }
                key = make_ipv4_flow_key(sip, dip, sport, dport, proto);
            }
            // ICMP has no ports but still important to track
            else if (proto == 1) {
                key = make_ipv4_flow_key(sip, dip, 0, 0, proto);
                proto_name = "ICMP";
            }
            // IGMP has no ports
            else if (proto == 2) {
                key = make_ipv4_flow_key(sip, dip, 0, 0, proto);
                proto_name = "IGMP";
            }
            else {
                continue;  // Skip unsupported protocols
            }
        }
        // ── IPv6 packets ──────────────────────────────────────────────────────
        else if (eth_type == 0x86DD) {
            if (rp.header.caplen < 14 + 40) continue;

            const u_char* ip6  = pkt + 14;
            uint8_t next_hdr   = ip6[6];  // Next Header field
            
            uint8_t sip6[16], dip6[16];
            std::memcpy(sip6, ip6 + 8, 16);
            std::memcpy(dip6, ip6 + 24, 16);
            packet_src_ip = ipv6_to_string(sip6);
            packet_dst_ip = ipv6_to_string(dip6);

            const u_char* l4 = ip6 + 40;
            uint16_t sport = 0, dport = 0;
            uint8_t proto = next_hdr;

            // For simplicity, ignore extension headers; just use the next_hdr value
            // (A full implementation would parse through extension headers)

            // TCP and UDP
            if (proto == 6 || proto == 17) {
                if (rp.header.caplen < 14 + 40 + 4) continue;
                sport = ntohs(*reinterpret_cast<const uint16_t*>(l4));
                dport = ntohs(*reinterpret_cast<const uint16_t*>(l4 + 2));
                packet_src_port = sport;
                packet_dst_port = dport;
                is_tcp_udp = true;

                if (proto == 6) {
                    if (rp.header.caplen >= 14 + 40 + 14) {
                        auto fl = parse_tcp_flags(l4);
                        tcp_syn = fl.syn;
                        tcp_ack = fl.ack;
                        tcp_fin = fl.fin;
                        tcp_rst = fl.rst;
                    }
                    proto_name = "TCP";
                } else {
                    proto_name = "UDP";
                }
                key = make_ipv6_flow_key(sip6, dip6, sport, dport, proto);
            }
            // ICMPv6 has no ports
            else if (proto == 58) {
                key = make_ipv6_flow_key(sip6, dip6, 0, 0, proto);
                proto_name = "ICMPv6";
            }
            else {
                continue;  // Skip unsupported IPv6 protocols
            }
        }
        else {
            continue;  // Skip non-IP packets
        }

        auto now    = std::chrono::steady_clock::now();

        // Only do process lookup for TCP/UDP (they have socket inodes in /proc/net).
        if (is_tcp_udp) {
            auto cached = manager_.get_cached_process(key);
            bool do_lookup = false;
            if (!cached) {
                auto it = last_lookup.find(key);
                if (it == last_lookup.end() ||
                    std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() >= 1) {
                    do_lookup = true;
                    last_lookup[key] = now;
                }
            }

            if (do_lookup) {
                parser.refresh();
                // Try to find process; parser handles TCP/UDP across IPv4 and IPv6.
                auto entry = parser.find_by_tuple(
                    packet_src_ip, packet_src_port,
                    packet_dst_ip, packet_dst_port,
                    key.proto
                );
                if (!entry) {
                    entry = parser.find_by_flow_key(key);
                }
                if (!entry) {
                    entry = parser.find_by_local_port(packet_src_port, key.proto);
                }
                if (!entry) {
                    entry = parser.find_by_local_port(packet_dst_port, key.proto);
                }
                if (entry) {
                    if (entry->inode != 0) {
                        if (auto pid_opt = parser.inode_to_pid(entry->inode)) {
                            pid_t pid = *pid_opt;
                            std::string name = read_process_name(pid);
                            ProcessInfo info; info.pid = pid; info.name = name;
                            manager_.cache_process(key, info);
                            last_lookup.erase(key);

                            emit newConnectionFound(
                                QString::fromStdString(key.ip1),
                                QString::fromStdString(key.ip2),
                                key.port1, key.port2,
                                QString::fromStdString(proto_name),
                                QString::fromStdString(name.empty()
                                    ? ("pid:" + std::to_string(pid)) : name)
                            );
                        }
                    }
                }
            }
        }

        // Update flow with all TCP flags
        manager_.update(key, packet_bytes, tcp_syn, tcp_ack, tcp_fin, tcp_rst);

        if (last_lookup.size() > MAX_LOOKUP_RETRY_TRACKING) {
            for (auto it = last_lookup.begin(); it != last_lookup.end(); ) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                               now - it->second).count();
                if (age > LOOKUP_RETRY_MAX_AGE_SEC) {
                    it = last_lookup.erase(it);
                } else {
                    ++it;
                }
            }
            while (last_lookup.size() > MAX_LOOKUP_RETRY_TRACKING && !last_lookup.empty()) {
                last_lookup.erase(last_lookup.begin());
            }
        }
    }
}
// ── Cleanup thread (runs independently for timeout-based flow closure) ────────
void SnifferBackend::cleanupThread() {
    while (running_.load()) {
        // Sleep for 5 seconds between cleanup cycles
        for (int i = 0; i < 50 && running_.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        if (!running_.load()) break;
        
        // Mark flows that have timed out as CLOSED
        manager_.mark_timed_out_flows();
        
        // Remove flows that have been CLOSED for too long from memory
        manager_.garbage_collect();
    }
}
