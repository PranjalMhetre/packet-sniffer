#pragma once
#include "cli.h"
#include "packet_queue.h"
#include "stats.h"
#include <pcap.h>
#include <thread>

class Capture {
public:
  Capture(const Config &cfg, Stats &stats);
  ~Capture();
  bool init();
  void start();

private:
  pcap_t *handle;
  Config cfg;
  Stats &stats;
  PacketQueue queue;
  std::thread parser_thread;

  static void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                             const u_char *packet);
  void parser_loop();
};
