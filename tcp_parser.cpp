#include "tcp_parser.h"
#include "flow_manager.h"  // For FlowKey
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <algorithm>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <cstring>
#include <cctype>
#include <array>

using namespace std;

// /proc/net/{tcp,udp} stores IPv4 addresses as little-endian hex words.
static string proc_ipv4_to_string(const string& hex) {
    if (hex.length() != 8) return "";

    try {
        uint32_t addr = static_cast<uint32_t>(stoul(hex, nullptr, 16));
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
            return string(buf);
        }
    } catch (...) {
    }
    return "";
}

// /proc/net/{tcp6,udp6} stores IPv6 as four little-endian 32-bit words.
static string proc_ipv6_to_string(const string& hex) {
    if (hex.length() != 32) return "";

    try {
        array<unsigned char, 16> addr{};
        for (int word = 0; word < 4; ++word) {
            for (int byte = 0; byte < 4; ++byte) {
                int src = word * 8 + (3 - byte) * 2;
                addr[word * 4 + byte] =
                    static_cast<unsigned char>(stoul(hex.substr(src, 2), nullptr, 16));
            }
        }

        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, addr.data(), buf, sizeof(buf))) {
            return string(buf);
        }
    } catch (...) {
    }
    return "";
}

static string ipv4_uint32_to_string(uint32_t addr) {
    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &addr, buf, sizeof(buf)) ? string(buf) : string();
}

// Convert hex port -> host-order uint16_t
static uint16_t hex_to_port_host_order(const string& hex) {
    uint16_t p = 0;
    try {
        p = static_cast<uint16_t>(stoul(hex, nullptr, 16));
    } catch (...) {
        return 0;
    }
    return p;
}

// Split "IP:PORT"
static pair<string, string> split_ip_port(const string& s) {
    size_t pos = s.find(':');
    if (pos == string::npos) return {"", ""};
    return {s.substr(0, pos), s.substr(pos + 1)};
}

static bool is_wildcard_ip(const string& ip) {
    return ip == "0.0.0.0" || ip == "::";
}

static bool endpoint_matches(const TcpEntry& e,
                             const string& local_ip, uint16_t local_port,
                             const string& remote_ip, uint16_t remote_port) {
    const bool local_ok =
        e.local_port == local_port &&
        (e.local_ip == local_ip || is_wildcard_ip(e.local_ip));
    const bool remote_ok =
        e.remote_port == remote_port &&
        (e.remote_ip == remote_ip || is_wildcard_ip(e.remote_ip));

    if (local_ok && remote_ok) return true;

    // Unconnected UDP sockets appear with remote 0.0.0.0:0 or [::]:0.
    return local_ok && e.remote_port == 0 && is_wildcard_ip(e.remote_ip);
}

void TcpParser::refresh_proc_table(const char* path, uint8_t protocol, bool ipv6) {
    ifstream file(path);
    if (!file.is_open()) {
        cerr << "[TcpParser] Failed to open " << path << "\n";
        return;
    }

    string line;
    getline(file, line);  // Skip header

    while (getline(file, line)) {
        auto start = line.find_first_not_of(" \t\r\n");
        if (start == string::npos) continue;
        string trimmed = line.substr(start);

        istringstream iss(trimmed);
        vector<string> tokens;
        string temp;

        while (iss >> temp) {
            tokens.push_back(temp);
        }

        if (tokens.size() < 10) continue;

        auto [lip_hex, lport_hex] = split_ip_port(tokens[1]);
        auto [rip_hex, rport_hex] = split_ip_port(tokens[2]);

        if (lip_hex.empty() || rip_hex.empty()) continue;

        try {
            string local_ip = ipv6 ? proc_ipv6_to_string(lip_hex)
                                   : proc_ipv4_to_string(lip_hex);
            string remote_ip = ipv6 ? proc_ipv6_to_string(rip_hex)
                                    : proc_ipv4_to_string(rip_hex);
            if (local_ip.empty() || remote_ip.empty()) continue;

            TcpEntry entry;
            entry.local_ip = local_ip;
            entry.local_port = hex_to_port_host_order(lport_hex);
            entry.remote_ip = remote_ip;
            entry.remote_port = hex_to_port_host_order(rport_hex);
            entry.inode = stoull(tokens[9]);
            entry.protocol = protocol;

            entries.push_back(entry);
        } catch (...) {
            continue;
        }
    }
}

void TcpParser::refresh() {
    entries.clear();
    refresh_proc_table("/proc/net/tcp", 6, false);
    refresh_proc_table("/proc/net/tcp6", 6, true);
    refresh_proc_table("/proc/net/udp", 17, false);
    refresh_proc_table("/proc/net/udp6", 17, true);
    refresh_inode_pid_cache();
}

optional<TcpEntry> TcpParser::find(uint32_t src_ip, uint16_t src_port,
                                   uint32_t dst_ip, uint16_t dst_port) {
    string src_ip_str = ipv4_uint32_to_string(src_ip);
    string dst_ip_str = ipv4_uint32_to_string(dst_ip);
    
    for (const auto& e : entries) {
        if (e.protocol != 6) continue;
        if (endpoint_matches(e, src_ip_str, src_port, dst_ip_str, dst_port) ||
            endpoint_matches(e, dst_ip_str, dst_port, src_ip_str, src_port)) {
            return e;
        }
    }
    return nullopt;
}

optional<TcpEntry> TcpParser::find_by_flow_key(const FlowKey& key) {
    return find_by_tuple(key.ip1, key.port1, key.ip2, key.port2, key.proto);
}

optional<TcpEntry> TcpParser::find_by_tuple(const string& src_ip, uint16_t src_port,
                                            const string& dst_ip, uint16_t dst_port,
                                            uint8_t protocol) {
    for (const auto& e : entries) {
        if (e.protocol != protocol) continue;
        if (endpoint_matches(e, src_ip, src_port, dst_ip, dst_port) ||
            endpoint_matches(e, dst_ip, dst_port, src_ip, src_port)) {
            return e;
        }
    }
    return nullopt;
}

optional<TcpEntry> TcpParser::find_by_local_port(uint16_t port, uint8_t protocol) {
    if (port == 0) return nullopt;

    optional<TcpEntry> wildcard_match;
    for (const auto& e : entries) {
        if (e.protocol != protocol || e.local_port != port) continue;

        if (!is_wildcard_ip(e.remote_ip) && e.remote_port != 0) {
            return e;
        }
        if (!wildcard_match) {
            wildcard_match = e;
        }
    }
    return wildcard_match;
}

void TcpParser::refresh_inode_pid_cache() {
    inode_pid_cache_.clear();

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        cerr << "[TcpParser] Failed to open /proc for PID mapping\n";
        return;
    }

    struct dirent* dent;
    while ((dent = readdir(proc_dir)) != nullptr) {
        if (!isdigit(static_cast<unsigned char>(dent->d_name[0]))) continue;

        string pid_str = dent->d_name;
        string fd_dir_path = string("/proc/") + pid_str + "/fd";

        DIR* fd_dir = opendir(fd_dir_path.c_str());
        if (!fd_dir) {
            continue;
        }

        struct dirent* fdent;
        while ((fdent = readdir(fd_dir)) != nullptr) {
            if (fdent->d_name[0] == '.') continue;

            string fd_path = fd_dir_path + "/" + fdent->d_name;
            char linkbuf[PATH_MAX];
            ssize_t r = readlink(fd_path.c_str(), linkbuf, sizeof(linkbuf) - 1);
            if (r <= 0) continue;
            linkbuf[r] = '\0';
            string target(linkbuf);

            if (target.size() >= 9 && target.rfind("socket:[", 0) == 0) {
                size_t lb = target.find('[');
                size_t rb = target.find(']');
                if (lb != string::npos && rb != string::npos && rb > lb + 1) {
                    string num = target.substr(lb + 1, rb - lb - 1);
                    try {
                        unsigned long long found_inode = stoull(num);
                        inode_pid_cache_.emplace(found_inode, static_cast<pid_t>(stoi(pid_str)));
                    } catch (...) {
                    }
                }
            }
        }

        closedir(fd_dir);
    }

    closedir(proc_dir);
}

optional<pid_t> TcpParser::inode_to_pid(uint64_t inode) {
    auto it = inode_pid_cache_.find(inode);
    if (it != inode_pid_cache_.end()) {
        return it->second;
    }
    return nullopt;
}
