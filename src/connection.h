#pragma once
#include <cstdint>
#include <ctime>
#include <string>
#include <unordered_map>

struct ConnectionKey {
  std::string src_ip;
  std::string dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;

  bool operator==(const ConnectionKey &other) const {
    return src_ip == other.src_ip && dst_ip == other.dst_ip &&
           src_port == other.src_port && dst_port == other.dst_port &&
           protocol == other.protocol;
  }
};

struct ConnectionKeyHash {
  size_t operator()(const ConnectionKey &k) const {
    size_t h = std::hash<std::string>{}(k.src_ip);
    h ^= std::hash<std::string>{}(k.dst_ip) << 1;
    h ^= std::hash<uint16_t>{}(k.src_port) << 2;
    h ^= std::hash<uint16_t>{}(k.dst_port) << 3;
    h ^= std::hash<uint8_t>{}(k.protocol) << 4;
    return h;
  }
};

struct ConnectionInfo {
  int packets = 0;
  uint64_t bytes = 0;
  time_t first_seen = 0;
  time_t last_seen = 0;
  std::string state = "UNKNOWN";
};

class ConnectionTable {
public:
  void update_tcp(const std::string &src_ip, const std::string &dst_ip,
                  uint16_t src_port, uint16_t dst_port, uint8_t flags,
                  uint32_t pkt_len);

  void update_udp(const std::string &src_ip, const std::string &dst_ip,
                  uint16_t src_port, uint16_t dst_port, uint32_t pkt_len);

  void print_summary() const;
  int size() const { return table.size(); }

private:
  std::unordered_map<ConnectionKey, ConnectionInfo, ConnectionKeyHash> table;

  ConnectionKey normalize(const std::string &src_ip, const std::string &dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t protocol) const;
};
