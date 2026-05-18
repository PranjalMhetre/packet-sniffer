#include "tcp.h"
#include <cstdio>
#include <iostream>
#include <netinet/in.h>

static std::string get_flag_string(uint8_t flags) {
  std::string result = "[";
  if (flags & TCP_SYN) {
    result += "SYN ";
  }
  if (flags & TCP_ACK) {
    result += "ACK ";
  }
  if (flags & TCP_FIN) {
    result += "FIN ";
  }
  if (flags & TCP_RST) {
    result += "RST ";
  }
  if (flags & TCP_PSH) {
    result += "PSH ";
  }
  if (flags & TCP_URG) {
    result += "URG ";
  }
  if (result.back() == ' ') {
    result.pop_back();
  }
  result += "]";
  return result;
}

static bool try_parse_http(const u_char *data, uint32_t len) {
  if (len == 0) {
    return false;
  }
  std::string payload(reinterpret_cast<const char *>(data), len);

  bool is_request =
      payload.substr(0, 3) == "GET" || payload.substr(0, 4) == "POST" ||
      payload.substr(0, 3) == "PUT" || payload.substr(0, 6) == "DELETE";
  bool is_response = payload.substr(0, 4) == "HTTP";
  if (!is_request && !is_response) {
    return false;
  }

  size_t line_end = payload.find("\r\n");
  if (line_end != std::string::npos) {
    printf("     HTTP: %s\n", payload.substr(0, line_end).c_str());
  }

  size_t host_pos = payload.find("Host: ");
  if (host_pos != std::string::npos) {
    size_t host_end = payload.find("\r\n", host_pos);
    if (host_end != std::string::npos) {
      printf("     %s\n",
             payload.substr(host_pos, host_end - host_pos).c_str());
    }
  }
  return true;
}

void parse_tcp(const u_char *data, uint32_t len, const std::string &src_ip,
               const std::string &dst_ip, const Config &cfg, Stats &stats) {
  if (len < sizeof(TCPHeader)) {
    return;
  }

  const TCPHeader *tcp = reinterpret_cast<const TCPHeader *>(data);
  uint16_t sport = ntohs(tcp->src_port);
  uint16_t dport = ntohs(tcp->dest_port);

  if (cfg.filter_port != -1 && sport != cfg.filter_port &&
      dport != cfg.filter_port) {
    return;
  }

  stats.connections.update_tcp(src_ip, dst_ip, sport, dport, tcp->flags, len);

  // top 4 bits of data_offset give header length in 32-bit words
  uint8_t tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
  if (tcp_hdr_len < 20) {
    return;
  }

  printf("TCP  %s:%-5d -> %s:%-5d  %s  seq=%u\n", src_ip.c_str(), sport,
         dst_ip.c_str(), dport, get_flag_string(tcp->flags).c_str(),
         ntohl(tcp->seq_num));

  const u_char *payload = data + tcp_hdr_len;
  uint32_t payload_len = len - tcp_hdr_len;

  if (sport == 80 || dport == 80) {
    if (try_parse_http(payload, payload_len))
      stats.http++;
  }
}
