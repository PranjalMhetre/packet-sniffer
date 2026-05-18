#pragma once
#include "cli.h"
#include "stats.h"
#include <cstdint>
#include <string>

struct TCPHeader {
  uint16_t src_port;
  uint16_t dest_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint8_t data_offset; // top 4 bits are header length in 32-bit words
  uint8_t flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_ptr;
} __attribute__((packed));

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

void parse_tcp(const u_char *data, uint32_t len, const std::string &src_ip,
               const std::string &dst_ip, const Config &cfg, Stats &stats);
