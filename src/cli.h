#pragma once
#include <string>

struct Config {
  std::string interface = "";
  std::string filter_host = "";
  int filter_port = -1;
  int packet_count = 0;
  bool verbose = false;
};

Config parse_args(int argc, char *argv[]);
