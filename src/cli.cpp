#include "cli.h"
#include <cstdlib>
#include <iostream>
#include <unistd.h>

Config parse_args(int argc, char *argv[]) {
  Config cfg;
  int opt;

  while ((opt = getopt(argc, argv, "i:h:p:n:v")) != -1) {
    switch (opt) {
    case 'i':
      cfg.interface = optarg;
      break;
    case 'h':
      cfg.filter_host = optarg;
      break;
    case 'p':
      cfg.filter_port = std::atoi(optarg);
      break;
    case 'n':
      cfg.packet_count = std::atoi(optarg);
      break;
    case 'v':
      cfg.verbose = true;
      break;
    default:
      std::cerr << "Usage: sudo ./sniffer [-i interface] "
                   "[-h host] [-p port] [-n count] [-v]\n";
      exit(1);
    }
  }
  return cfg;
}
