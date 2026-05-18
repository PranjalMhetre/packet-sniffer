#pragma once
#include "connection.h"
#include <string>
#include <unordered_map>

struct Stats {
  int total = 0;
  int tcp = 0;
  int udp = 0;
  int arp = 0;
  int icmp = 0;
  int http = 0;
  int dns = 0;
  std::unordered_map<std::string, int> host_counts;
  ConnectionTable connections;
};
