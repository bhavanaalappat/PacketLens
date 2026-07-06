// tcp_parser.h
#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include <vector>
#include <cstdint>
#include <optional>
#include <sys/types.h>
#include <string>
#include <unordered_map>

struct TcpEntry {
    // Can be IPv4 (stored as dotted decimal string) or IPv6
    std::string local_ip;
    uint16_t local_port;    // host byte order numeric
    std::string remote_ip;
    uint16_t remote_port;
    uint64_t inode;
    uint8_t protocol;       // 6 = TCP, 17 = UDP
};

// Forward declaration
struct FlowKey;

class TcpParser {
public:
    std::vector<TcpEntry> entries;

    void refresh();  // Reads TCP/UDP sockets and refreshes inode -> PID cache

    std::optional<TcpEntry> find(uint32_t src_ip, uint16_t src_port,
                                 uint32_t dst_ip, uint16_t dst_port);

    // Find entry by FlowKey (supports both IPv4 and IPv6)
    std::optional<TcpEntry> find_by_flow_key(const FlowKey& key);
    std::optional<TcpEntry> find_by_tuple(const std::string& src_ip, uint16_t src_port,
                                          const std::string& dst_ip, uint16_t dst_port,
                                          uint8_t protocol);
    std::optional<TcpEntry> find_by_local_port(uint16_t port, uint8_t protocol);

    std::optional<pid_t> inode_to_pid(uint64_t inode);

private:
    void refresh_proc_table(const char* path, uint8_t protocol, bool ipv6);
    void refresh_inode_pid_cache();

    std::unordered_map<uint64_t, pid_t> inode_pid_cache_;
};

#endif
