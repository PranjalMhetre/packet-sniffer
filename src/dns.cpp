#include "dns.h"
#include <cstdio>
#include <iostream>
#include <netinet/in.h>

// DNS stores names as length-prefixed labels: 06google03com00
// compression pointers (top 2 bits = 0xC0) reference earlier offsets
static std::string parse_dns_name(const u_char *data, uint32_t len,
                                  uint32_t offset) {
  std::string name;
  uint32_t pos = offset;
  int jumps = 0;

  while (pos < len) {
    uint8_t label_len = data[pos];

    if (label_len == 0) {
      break;
    }

    if ((label_len & 0xC0) == 0xC0) {
      if (pos + 1 >= len) {
        break;
      }
      pos = ((label_len & 0x3F) << 8) | data[pos + 1];
      if (++jumps > 10) {
        break;
      }
      continue;
    }

    pos++;
    if (!name.empty()) {
      name += ".";
    }
    for (uint8_t i = 0; i < label_len && pos < len; i++, pos++)
      name += static_cast<char>(data[pos]);
  }

  return name;
}

void parse_dns(const u_char *data, uint32_t len, const Config & /*cfg*/) {
  if (len < sizeof(DNSHeader)) {
    return;
  }

  const DNSHeader *dns = reinterpret_cast<const DNSHeader *>(data);

  uint16_t flags = ntohs(dns->flags);
  uint16_t qdcount = ntohs(dns->qdcount);
  uint16_t ancount = ntohs(dns->ancount);
  bool is_response = (flags & DNS_QR) != 0;

  uint32_t offset = sizeof(DNSHeader);

  for (uint16_t i = 0; i < qdcount && offset < len; i++) {
    std::string qname = parse_dns_name(data, len, offset);

    while (offset < len) {
      if (data[offset] == 0) {
        offset++;
        break;
      }
      if ((data[offset] & 0xC0) == 0xC0) {
        offset += 2;
        break;
      }
      offset += data[offset] + 1;
    }

    if (offset + 4 > len) {
      break;
    }
    uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t *>(data + offset));
    offset += 4;

    std::string type_str;
    if (qtype == 1) {
      type_str = "A";
    } else if (qtype == 28) {
      type_str = "AAAA";
    } else if (qtype == 15) {
      type_str = "MX";
    } else if (qtype == 5) {
      type_str = "CNAME";
    } else {
      type_str = "type=" + std::to_string(qtype);
    }

    if (!is_response) {
      printf("DNS  QUERY  %-5s %s\n", type_str.c_str(), qname.c_str());
    }
  }

  for (uint16_t i = 0; i < ancount && offset < len; i++) {
    std::string aname = parse_dns_name(data, len, offset);

    while (offset < len) {
      if (data[offset] == 0) {
        offset++;
        break;
      }
      if ((data[offset] & 0xC0) == 0xC0) {
        offset += 2;
        break;
      }
      offset += data[offset] + 1;
    }

    if (offset + 10 > len) {
      break;
    }

    uint16_t atype = ntohs(*reinterpret_cast<const uint16_t *>(data + offset));
    offset += 2;
    offset += 2;
    uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t *>(data + offset));
    offset += 4;
    uint16_t rdlen = ntohs(*reinterpret_cast<const uint16_t *>(data + offset));
    offset += 2;

    if (atype == 1 && rdlen == 4 && offset + 4 <= len) {
      printf("DNS  REPLY  A     %s -> %d.%d.%d.%d  ttl=%ds\n", aname.c_str(),
             data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
             ttl);
    } else if (atype == 28 && rdlen == 16 && offset + 16 <= len) {
      printf("DNS  REPLY  AAAA  %s  ttl=%ds\n", aname.c_str(), ttl);
    } else if (atype == 5) {
      std::string cname = parse_dns_name(data, len, offset);
      printf("DNS  REPLY  CNAME %s -> %s  ttl=%ds\n", aname.c_str(),
             cname.c_str(), ttl);
    }

    offset += rdlen;
  }
}
