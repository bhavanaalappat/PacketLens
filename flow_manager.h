#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <optional>
#include <cstdint>
#include <sys/types.h>
#include <arpa/inet.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <functional>
#include <list>

// ── FlowKey (supports IPv4 and IPv6 addresses as canonical strings) ──────────
struct FlowKey {
    std::string host = "local";
    std::string ip1;    // canonical IP (e.g., "192.168.1.1" or "2001:db8::1")
    std::string ip2;
    uint16_t port1;     // host byte order (0 for ICMP/IGMP)
    uint16_t port2;     // host byte order (0 for ICMP/IGMP)
    uint8_t  proto;     // 6=TCP, 17=UDP, 1=ICMP, 2=IGMP, 58=ICMPv6

    bool operator==(const FlowKey& o) const {
        return host == o.host &&
               ip1 == o.ip1 && ip2 == o.ip2 &&
               port1 == o.port1 && port2 == o.port2 &&
               proto == o.proto;
    }
};

struct FlowHash {
    size_t operator()(const FlowKey& k) const {
        std::hash<std::string> sh;
        return sh(k.host) ^ (sh(k.ip1) << 1) ^ (sh(k.ip2) << 2) ^
               (((size_t)k.port1) << 2) ^ (((size_t)k.port2) << 3) ^
               (((size_t)k.proto) << 4);
    }
};

// Helper: Convert IPv4 address from network byte order to canonical string
inline std::string ipv4_to_string(uint32_t addr) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

// Helper: Convert IPv6 address to canonical string
inline std::string ipv6_to_string(const uint8_t addr[16]) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return std::string(buf);
}

// Create flow key from IPv4 addresses
inline FlowKey make_ipv4_flow_key(uint32_t sip, uint32_t dip,
                                   uint16_t sport, uint16_t dport, uint8_t proto,
                                   const std::string& host = "local") {
    auto s = ipv4_to_string(sip);
    auto d = ipv4_to_string(dip);
    FlowKey k;
    k.host = host;
    if (s < d || (s == d && sport <= dport)) {
        k.ip1 = s; k.ip2 = d; k.port1 = sport; k.port2 = dport;
    } else {
        k.ip1 = d; k.ip2 = s; k.port1 = dport; k.port2 = sport;
    }
    k.proto = proto;
    return k;
}

// Create flow key from IPv6 addresses
inline FlowKey make_ipv6_flow_key(const uint8_t sip[16], const uint8_t dip[16],
                                   uint16_t sport, uint16_t dport, uint8_t proto,
                                   const std::string& host = "local") {
    auto s = ipv6_to_string(sip);
    auto d = ipv6_to_string(dip);
    FlowKey k;
    k.host = host;
    if (s < d || (s == d && sport <= dport)) {
        k.ip1 = s; k.ip2 = d; k.port1 = sport; k.port2 = dport;
    } else {
        k.ip1 = d; k.ip2 = s; k.port1 = dport; k.port2 = sport;
    }
    k.proto = proto;
    return k;
}

// Create flow key from string IPs (for lookup from /proc/net/tcp6)
inline FlowKey make_string_flow_key(const std::string& sip, const std::string& dip,
                                      uint16_t sport, uint16_t dport, uint8_t proto,
                                      const std::string& host = "local") {
    FlowKey k;
    k.host = host;
    if (sip < dip || (sip == dip && sport <= dport)) {
        k.ip1 = sip; k.ip2 = dip; k.port1 = sport; k.port2 = dport;
    } else {
        k.ip1 = dip; k.ip2 = sip; k.port1 = dport; k.port2 = sport;
    }
    k.proto = proto;
    return k;
}

// ── Flow State Machine (TCP-aware) ───────────────────────────────────────────
// Tracks proper TCP state transitions + timeout-based closure for UDP/ICMP
enum FlowState {
    FLOW_NEW,           // Initial state, no significant activity
    FLOW_SYN_SENT,      // TCP: SYN sent, waiting for response
    FLOW_ESTABLISHED,   // TCP: SYN-ACK received & ACK sent; UDP/ICMP: 1+ packet
    FLOW_FIN_WAITING,   // TCP: FIN sent, awaiting FIN/RST
    FLOW_CLOSED         // TCP: FIN/RST received; UDP/ICMP: timed out
};

struct FlowData {
    uint64_t packets = 0;
    uint64_t bytes   = 0;
    FlowState state  = FLOW_NEW;
    std::chrono::steady_clock::time_point last_seen;
    std::chrono::steady_clock::time_point closed_at;  // When marked as CLOSED (for grace period)
    
    // TCP flag tracking for proper state machine
    bool tcp_syn_seen     = false;  // SYN packet seen
    bool tcp_ack_seen     = false;  // ACK packet seen (indicates established)
    bool tcp_fin_seen     = false;  // FIN packet seen
    bool tcp_rst_seen     = false;  // RST packet seen
    bool tcp_fin_rst_seen = false;  // Combined flag (legacy support)
    std::list<FlowKey>::iterator lru_it;

    FlowData() : last_seen(std::chrono::steady_clock::now()) {}
};

struct ProcessInfo {
    pid_t       pid  = 0;
    std::string name;
};

// ── Snapshot row (what the GUI displays) ─────────────────────────────────────
struct FlowSnapshot {
    std::string host = "local";
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port  = 0;
    uint16_t    dst_port  = 0;
    std::string protocol; // "TCP" / "UDP"
    uint64_t    packets   = 0;
    uint64_t    bytes     = 0;
    std::string process;
    std::string state;
};

// ── FlowManager ───────────────────────────────────────────────────────────────
class FlowManager {
public:
    // Timeouts for different protocols and states
    static constexpr int TCP_FIN_TIMEOUT_SEC = 60;  // How long to keep FIN_WAITING state visible
    static constexpr int TCP_CLOSED_TIMEOUT_SEC = 30;  // How long to keep CLOSED state visible
    static constexpr int TCP_IDLE_TIMEOUT_SEC = 120;   // Idle TCP connection timeout
    static constexpr int UDP_TIMEOUT_SEC = 30;     // UDP flow timeout
    static constexpr int ICMP_TIMEOUT_SEC = 10;    // ICMP flow timeout
    static constexpr int GC_REMOVE_DELAY_SEC = 20; // How long CLOSED flows stay in memory
    static constexpr size_t MAX_TRACKED_FLOWS = 10000;
    static constexpr size_t FLOW_EVICT_BATCH = 512;

    // Enhanced update with TCP flag support
    void update(const FlowKey& key, uint32_t bytes,
                bool tcp_syn, bool tcp_ack, bool tcp_fin, bool tcp_rst) {
        std::unique_lock<std::mutex> lk(mtx_);

        auto it = flows_.find(key);
        if (it == flows_.end()) {
            lru_.push_front(key);
            auto inserted = flows_.emplace(key, FlowData{});
            it = inserted.first;
            it->second.lru_it = lru_.begin();
        } else {
            touch_lru_locked(it->first, it->second);
        }

        auto& data = it->second;
        data.packets++;
        data.bytes += bytes;
        data.last_seen = std::chrono::steady_clock::now();
        total_packets_++;
        total_bytes_ += bytes;

        if (key.proto == 6) {  // TCP
            // Track all flags
            if (tcp_syn) data.tcp_syn_seen = true;
            if (tcp_ack) data.tcp_ack_seen = true;
            if (tcp_fin) data.tcp_fin_seen = true;
            if (tcp_rst) data.tcp_rst_seen = true;
            data.tcp_fin_rst_seen = tcp_fin || tcp_rst;  // Legacy flag
            
            // State machine transitions
            if (data.state == FLOW_NEW && tcp_syn && !tcp_ack) {
                data.state = FLOW_SYN_SENT;
            }
            else if (data.state == FLOW_SYN_SENT && tcp_ack) {
                data.state = FLOW_ESTABLISHED;
            }
            else if (data.state == FLOW_NEW && tcp_ack) {
                // ACK without SYN (response to SYN from other side)
                data.state = FLOW_ESTABLISHED;
            }
            else if ((data.state == FLOW_ESTABLISHED || data.state == FLOW_SYN_SENT) && (tcp_fin || tcp_rst)) {
                data.state = FLOW_CLOSED;
                data.closed_at = std::chrono::steady_clock::now();
            }
        }
        else if (key.proto == 17) {  // UDP
            if (data.state == FLOW_NEW) {
                data.state = FLOW_ESTABLISHED;
            }
        }
        else if (key.proto == 1 || key.proto == 58) {  // ICMP / ICMPv6
            if (data.state == FLOW_NEW) {
                data.state = FLOW_ESTABLISHED;
            }
        }
        else if (key.proto == 2) {  // IGMP
            if (data.state == FLOW_NEW) {
                data.state = FLOW_ESTABLISHED;
            }
        }

        enforce_flow_cap_locked();
    }

    std::optional<ProcessInfo> get_cached_process(const FlowKey& key) {
        std::unique_lock<std::mutex> lk(mtx_);
        auto it = proc_cache_.find(key);
        if (it != proc_cache_.end()) return it->second;
        return std::nullopt;
    }

    void cache_process(const FlowKey& key, const ProcessInfo& info) {
        std::unique_lock<std::mutex> lk(mtx_);
        proc_cache_[key] = info;
    }

    void ingest_remote_snapshot(const FlowSnapshot& snap) {
        uint8_t proto = 0;
        if (snap.protocol == "TCP") proto = 6;
        else if (snap.protocol == "UDP") proto = 17;
        else if (snap.protocol == "ICMP") proto = 1;
        else if (snap.protocol == "IGMP") proto = 2;
        else if (snap.protocol == "ICMPv6") proto = 58;
        if (proto == 0 || snap.src_ip.empty() || snap.dst_ip.empty()) return;

        FlowKey key = make_string_flow_key(
            snap.src_ip,
            snap.dst_ip,
            snap.src_port,
            snap.dst_port,
            proto,
            snap.host.empty() ? "remote" : snap.host
        );

        std::unique_lock<std::mutex> lk(mtx_);
        auto it = flows_.find(key);
        if (it == flows_.end()) {
            lru_.push_front(key);
            auto inserted = flows_.emplace(key, FlowData{});
            it = inserted.first;
            it->second.lru_it = lru_.begin();
        } else {
            touch_lru_locked(it->first, it->second);
        }

        auto& data = it->second;
        if (snap.packets > data.packets) total_packets_ += snap.packets - data.packets;
        if (snap.bytes > data.bytes) total_bytes_ += snap.bytes - data.bytes;
        data.packets = std::max<uint64_t>(data.packets, snap.packets);
        data.bytes = std::max<uint64_t>(data.bytes, snap.bytes);
        data.last_seen = std::chrono::steady_clock::now();
        if (snap.state == "CLOSED") {
            data.state = FLOW_CLOSED;
            data.closed_at = data.last_seen;
        } else if (snap.state == "SYN-SENT") {
            data.state = FLOW_SYN_SENT;
        } else if (snap.state == "FIN-WAIT") {
            data.state = FLOW_FIN_WAITING;
        } else if (snap.state == "EST") {
            data.state = FLOW_ESTABLISHED;
        }

        if (!snap.process.empty()) {
            ProcessInfo info;
            info.name = snap.process;
            proc_cache_[key] = info;
        }

        enforce_flow_cap_locked();
    }

    void clear() {
        std::unique_lock<std::mutex> lk(mtx_);
        flows_.clear();
        proc_cache_.clear();
        lru_.clear();
        total_packets_ = 0;
        total_bytes_ = 0;
    }

    // Mark timed-out flows as CLOSED (transitions them without removing)
    void mark_timed_out_flows() {
        std::unique_lock<std::mutex> lk(mtx_);
        auto now = std::chrono::steady_clock::now();
        for (auto& [key, data] : flows_) {
            if (data.state == FLOW_CLOSED) continue;  // Already closed
            
            auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(
                                   now - data.last_seen).count();
            int timeout = TCP_IDLE_TIMEOUT_SEC;  // Default for TCP
            
            // Determine timeout based on protocol
            if (key.proto == 6) {  // TCP
                if (data.state == FLOW_SYN_SENT) {
                    timeout = 10;  // SYN timeout
                } else if (data.state == FLOW_ESTABLISHED) {
                    timeout = TCP_IDLE_TIMEOUT_SEC;
                } else {
                    continue;  // Other states
                }
            } else if (key.proto == 17) {  // UDP
                timeout = UDP_TIMEOUT_SEC;
            } else if (key.proto == 1 || key.proto == 58) {  // ICMP / ICMPv6
                timeout = ICMP_TIMEOUT_SEC;
            } else if (key.proto == 2) {  // IGMP
                timeout = UDP_TIMEOUT_SEC;
            }
            
            if (elapsed_sec > timeout) {
                data.state = FLOW_CLOSED;
                data.closed_at = now;
            }
        }
    }
    
    // Remove flows that have been CLOSED for too long (cleanup memory)
    void garbage_collect() {
        std::unique_lock<std::mutex> lk(mtx_);
        auto now = std::chrono::steady_clock::now();
        for (auto it = flows_.begin(); it != flows_.end(); ) {
            const auto& data = it->second;
            
            // Only remove CLOSED flows after grace period
            if (data.state == FLOW_CLOSED) {
                auto closed_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                          now - data.closed_at).count();
                if (closed_elapsed > GC_REMOVE_DELAY_SEC) {
                    lru_.erase(it->second.lru_it);
                    proc_cache_.erase(it->first);
                    it = flows_.erase(it);
                } else {
                    ++it;
                }
            } else {
                ++it;
            }
        }

        enforce_flow_cap_locked();
    }

    // Thread-safe snapshot for the GUI — called every 1 s from QTimer
    std::vector<FlowSnapshot> get_snapshot() {
        std::unique_lock<std::mutex> lk(mtx_);
        std::vector<FlowSnapshot> out;
        out.reserve(flows_.size());

        for (auto& [key, data] : flows_) {
            FlowSnapshot s;
            s.host     = key.host;
            s.src_ip   = key.ip1;
            s.dst_ip   = key.ip2;
            s.src_port = key.port1;
            s.dst_port = key.port2;
            
            // Get protocol name from protocol number
            switch (key.proto) {
                case 1:   s.protocol = "ICMP";  break;
                case 2:   s.protocol = "IGMP";  break;
                case 6:   s.protocol = "TCP";   break;
                case 17:  s.protocol = "UDP";   break;
                case 58:  s.protocol = "ICMPv6"; break;
                default:  s.protocol = "OTHER"; break;
            }
            
            s.packets  = data.packets;
            s.bytes    = data.bytes;

            auto pit = proc_cache_.find(key);
            if (pit != proc_cache_.end()) {
                s.process = pit->second.name.empty()
                            ? ("pid:" + std::to_string(pit->second.pid))
                            : pit->second.name;
            }

            switch (data.state) {
                case FLOW_NEW:         s.state = "NEW";      break;
                case FLOW_SYN_SENT:    s.state = "SYN-SENT"; break;
                case FLOW_ESTABLISHED: s.state = "EST";      break;
                case FLOW_FIN_WAITING: s.state = "FIN-WAIT"; break;
                case FLOW_CLOSED:      s.state = "CLOSED";   break;
            }
            out.push_back(std::move(s));
        }
        return out;
    }

    size_t get_flow_count() {
        std::unique_lock<std::mutex> lk(mtx_);
        return flows_.size();
    }

    uint64_t total_packets() {
        std::unique_lock<std::mutex> lk(mtx_);
        return total_packets_;
    }

    uint64_t total_bytes() {
        std::unique_lock<std::mutex> lk(mtx_);
        return total_bytes_;
    }

private:
    void touch_lru_locked(const FlowKey& key, FlowData& data) {
        lru_.erase(data.lru_it);
        lru_.push_front(key);
        data.lru_it = lru_.begin();
    }

    void erase_flow_locked(
        std::unordered_map<FlowKey, FlowData, FlowHash>::iterator it) {
        lru_.erase(it->second.lru_it);
        proc_cache_.erase(it->first);
        flows_.erase(it);
    }

    void enforce_flow_cap_locked() {
        if (flows_.size() <= MAX_TRACKED_FLOWS) return;

        size_t target = MAX_TRACKED_FLOWS > FLOW_EVICT_BATCH
            ? MAX_TRACKED_FLOWS - FLOW_EVICT_BATCH
            : MAX_TRACKED_FLOWS;

        for (auto it = flows_.begin(); flows_.size() > target && it != flows_.end(); ) {
            if (it->second.state == FLOW_CLOSED) {
                auto erase_it = it++;
                erase_flow_locked(erase_it);
            } else {
                ++it;
            }
        }

        while (flows_.size() > target && !lru_.empty()) {
            auto victim = flows_.find(lru_.back());
            if (victim == flows_.end()) {
                lru_.pop_back();
                continue;
            }
            erase_flow_locked(victim);
        }
    }

    std::unordered_map<FlowKey, FlowData,    FlowHash> flows_;
    std::unordered_map<FlowKey, ProcessInfo, FlowHash> proc_cache_;
    std::list<FlowKey> lru_;
    std::mutex  mtx_;
    uint64_t    total_packets_ = 0;
    uint64_t    total_bytes_   = 0;
};
