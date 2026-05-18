#include "ethernet.h"
#include "ip.h"
#include <cstdio>
#include <iostream>
#include <netinet/in.h>

void parse_ethernet(const u_char *packet, uint32_t len, const Config &cfg,
                    Stats &stats) {
  if (len < sizeof(EthernetHeader)) {
    return;
  }
  const EthernetHeader *eth = reinterpret_cast<const EthernetHeader *>(packet);
  uint16_t type = ntohs(eth->ethertype);

  if (cfg.verbose) {
    printf("ETH  %02x:%02x:%02x:%02x:%02x:%02x -> "
           "%02x:%02x:%02x:%02x:%02x:%02x  type=0x%04x\n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2], eth->src_mac[3],
           eth->src_mac[4], eth->src_mac[5], eth->dest_mac[0], eth->dest_mac[1],
           eth->dest_mac[2], eth->dest_mac[3], eth->dest_mac[4],
           eth->dest_mac[5], type);
  }

  const u_char *payload = packet + sizeof(EthernetHeader);
  uint32_t payload_len = len - sizeof(EthernetHeader);

  if (type == ETHERTYPE_IP) {
    parse_ip(payload, payload_len, cfg, stats);
  } else if (type == ETHERTYPE_ARP) {
    stats.arp++;
    if (cfg.verbose)
      std::cout << "ARP packet\n";
  } else if (type == ETHERTYPE_IPV6) {
    if (cfg.verbose)
      std::cout << "IPv6 packet (not handled)\n";
  }
}
