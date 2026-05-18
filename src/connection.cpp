#include "connection.h"
#include <algorithm>
#include <cstdio>
#include <iostream>
#include <vector>

#define F_SYN 0x02
#define F_ACK 0x10
#define F_FIN 0x01
#define F_RST 0x04

// always put the lower IP first so both directions map to the same key
ConnectionKey ConnectionTable::normalize(const std::string &src_ip,
                                         const std::string &dst_ip,
                                         uint16_t src_port, uint16_t dst_port,
                                         uint8_t protocol) const {
  if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
    return {src_ip, dst_ip, src_port, dst_port, protocol};
  }
  return {dst_ip, src_ip, dst_port, src_port, protocol};
}

void ConnectionTable::update_tcp(const std::string &src_ip,
                                 const std::string &dst_ip, uint16_t src_port,
                                 uint16_t dst_port, uint8_t flags,
                                 uint32_t pkt_len) {
  ConnectionKey key = normalize(src_ip, dst_ip, src_port, dst_port, 6);
  ConnectionInfo &info = table[key];

  info.packets++;
  info.bytes += pkt_len;
  info.last_seen = time(nullptr);
  if (info.first_seen == 0) {
    info.first_seen = info.last_seen;
  }

  if (flags & F_RST) {
    info.state = "RESET";
  } else if ((flags & F_FIN) && (flags & F_ACK)) {
    info.state = "CLOSING";
  } else if (flags & F_FIN) {
    info.state = "FIN_WAIT";
  } else if ((flags & F_SYN) && (flags & F_ACK)) {
    info.state = "ESTABLISHED";
  } else if (flags & F_SYN) {
    info.state = "SYN_SENT";
  } else if ((flags & F_ACK) &&
             (info.state == "SYN_SENT" || info.state == "UNKNOWN")) {
    info.state = "ESTABLISHED";
  }
}

void ConnectionTable::update_udp(const std::string &src_ip,
                                 const std::string &dst_ip, uint16_t src_port,
                                 uint16_t dst_port, uint32_t pkt_len) {
  ConnectionKey key = normalize(src_ip, dst_ip, src_port, dst_port, 17);
  ConnectionInfo &info = table[key];

  info.packets++;
  info.bytes += pkt_len;
  info.last_seen = time(nullptr);
  if (info.first_seen == 0) {
    info.first_seen = info.last_seen;
    info.state = "UDP";
  }
}

void ConnectionTable::print_summary() const {
  if (table.empty()) {
    return;
  }

  std::cout << "\n=== Connection Table ===\n";
  printf("%-22s %-22s %-6s %-7s %-12s\n", "Source", "Destination", "Proto",
         "Packets", "Bytes");
  std::cout << std::string(75, '-') << "\n";

  std::vector<std::pair<ConnectionKey, ConnectionInfo>> conns(table.begin(),
                                                              table.end());

  std::sort(conns.begin(), conns.end(), [](const auto &a, const auto &b) {
    return a.second.packets > b.second.packets;
  });

  int limit = std::min((int)conns.size(), 10);
  for (int i = 0; i < limit; i++) {
    const auto &key = conns[i].first;
    const auto &info = conns[i].second;

    std::string proto = (key.protocol == 6) ? "TCP" : "UDP";
    std::string bytes_str;
    if (info.bytes >= 1024 * 1024) {
      bytes_str = std::to_string(info.bytes / (1024 * 1024)) + " MB";
    } else if (info.bytes >= 1024) {
      bytes_str = std::to_string(info.bytes / 1024) + " KB";
    } else {
      bytes_str = std::to_string(info.bytes) + " B";
    }

    std::string src = key.src_ip + ":" + std::to_string(key.src_port);
    std::string dst = key.dst_ip + ":" + std::to_string(key.dst_port);

    printf("%-22s %-22s %-6s %-7d %-12s %s\n", src.c_str(), dst.c_str(),
           proto.c_str(), info.packets, bytes_str.c_str(), info.state.c_str());
  }
  std::cout << "========================\n";
}
