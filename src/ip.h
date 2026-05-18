#pragma once
#include "cli.h"
#include "stats.h"
#include <cstdint>

struct IPHeader {
  uint8_t version_ihl; // top 4 bits = version, bottom 4 = header length
  uint8_t tos;
  uint16_t total_length;
  uint16_t identification;
  uint16_t flags_fragment;
  uint8_t ttl;
  uint8_t protocol; // 6=TCP, 17=UDP, 1=ICMP
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dest_ip;
} __attribute__((packed));

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

void parse_ip(const u_char *data, uint32_t len, const Config &cfg,
              Stats &stats);
