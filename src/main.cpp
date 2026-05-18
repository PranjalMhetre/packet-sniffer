#include "capture.h"
#include "cli.h"
#include "stats.h"
#include <algorithm>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <vector>

Stats g_stats;

void print_summary() {
  std::cout << "\n=== Session Summary ===\n";
  std::cout << "Total packets : " << g_stats.total << "\n";
  std::cout << "TCP           : " << g_stats.tcp << "\n";
  std::cout << "UDP           : " << g_stats.udp << "\n";
  std::cout << "ARP           : " << g_stats.arp << "\n";
  std::cout << "ICMP          : " << g_stats.icmp << "\n";
  std::cout << "HTTP          : " << g_stats.http << "\n";
  std::cout << "DNS           : " << g_stats.dns << "\n";
  std::cout << "Unique hosts  : " << g_stats.host_counts.size() << "\n";

  if (!g_stats.host_counts.empty()) {
    std::cout << "\nTop hosts:\n";

    std::vector<std::pair<std::string, int>> hosts(g_stats.host_counts.begin(),
                                                   g_stats.host_counts.end());

    std::sort(hosts.begin(), hosts.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });

    int limit = std::min((int)hosts.size(), 5);
    for (int i = 0; i < limit; i++)
      printf("  %-18s %d packets\n", hosts[i].first.c_str(), hosts[i].second);
  }

  g_stats.connections.print_summary();
  std::cout << "======================\n";
}

void signal_handler(int /*signum*/) {
  std::cout << "\nCapture stopped.\n";
  print_summary();
  exit(0);
}

int main(int argc, char *argv[]) {
  signal(SIGINT, signal_handler);

  Config cfg = parse_args(argc, argv);

  std::cout << "=== Packet Sniffer ===\n";
  if (!cfg.interface.empty()){
    std::cout << "Interface  : " << cfg.interface << "\n";
  }
  if (!cfg.filter_host.empty()){
    std::cout << "Host filter: " << cfg.filter_host << "\n";
  }
  if (cfg.filter_port != -1){
    std::cout << "Port filter: " << cfg.filter_port << "\n";
  }
  if (cfg.packet_count > 0){
    std::cout << "Packet limit: " << cfg.packet_count << "\n";
  }
  std::cout << "======================\n\n";

  Capture capture(cfg, g_stats);

  if (!capture.init()) {
    std::cerr << "Failed to initialize capture. "
              << "Make sure you're running with sudo.\n";
    return 1;
  }

  capture.start();
  return 0;
}
