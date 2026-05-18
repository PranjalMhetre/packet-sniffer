#pragma once
#include "cli.h"
#include <cstdint>
#include <string>

struct DNSHeader {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} __attribute__((packed));

#define DNS_QR 0x8000    // 0 = query, 1 = response
#define DNS_RCODE 0x000F // bottom 4 bits = response code

void parse_dns(const u_char *data, uint32_t len, const Config &cfg);
