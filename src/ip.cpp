#include "dns.h"
#include "ip.h"
#include "tcp.h"
#include <arpa/inet.h>
#include <cstdio>
#include <iostream>
#include <netinet/in.h>

void parse_ip(const u_char *data, uint32_t len, const Config &cfg,
              Stats &stats) {
  if (len < sizeof(IPHeader)){
    return;
  }

  const IPHeader *ip = reinterpret_cast<const IPHeader *>(data);

  // IHL is the bottom 4 bits, counts 32-bit words, so multiply by 4
  uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
  if (ihl < 20){
    return;
  }
  struct in_addr src_addr, dst_addr;
  src_addr.s_addr = ip->src_ip;
  dst_addr.s_addr = ip->dest_ip;
  std::string src_ip = inet_ntoa(src_addr);
  std::string dst_ip = inet_ntoa(dst_addr);

  stats.host_counts[src_ip]++;
  stats.host_counts[dst_ip]++;

  if (!cfg.filter_host.empty() && src_ip != cfg.filter_host &&
      dst_ip != cfg.filter_host){
    return;
      }

  if (cfg.verbose) {
    printf("IP   %-15s -> %-15s  proto=%d  ttl=%d  len=%d\n", src_ip.c_str(),
           dst_ip.c_str(), ip->protocol, ip->ttl, ntohs(ip->total_length));
  }

  const u_char *payload = data + ihl;
  uint32_t payload_len = len - ihl;

  if (ip->protocol == IP_PROTO_TCP) {
    stats.tcp++;
    parse_tcp(payload, payload_len, src_ip, dst_ip, cfg, stats);
  } else if (ip->protocol == IP_PROTO_UDP) {
    stats.udp++;
    if (cfg.verbose){
      std::cout << "UDP  " << src_ip << " -> " << dst_ip << "\n";
    }
    stats.connections.update_udp(
        src_ip, dst_ip, ntohs(*reinterpret_cast<const uint16_t *>(payload)),
        ntohs(*reinterpret_cast<const uint16_t *>(payload + 2)), payload_len);

    if ((ntohs(*reinterpret_cast<const uint16_t *>(payload + 2)) == 53 ||
         ntohs(*reinterpret_cast<const uint16_t *>(payload)) == 53) &&
        payload_len > 8) {
      stats.dns++;
      parse_dns(payload + 8, payload_len - 8, cfg);
    }
  } else if (ip->protocol == IP_PROTO_ICMP) {
    stats.icmp++;
    if (cfg.verbose){
      std::cout << "ICMP " << src_ip << " -> " << dst_ip << "\n";
    }
  }
}
