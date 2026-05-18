#pragma once
#include "cli.h"
#include "stats.h"
#include <cstdint>

struct EthernetHeader {
  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint16_t ethertype;
} __attribute__((packed));

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

void parse_ethernet(const u_char *packet, uint32_t len, const Config &cfg,
                    Stats &stats);
