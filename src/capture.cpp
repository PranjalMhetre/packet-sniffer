#include "capture.h"
#include "ethernet.h"
#include <iostream>

Capture::Capture(const Config &cfg, Stats &stats)
    : handle(nullptr), cfg(cfg), stats(stats), queue(10000) {}

Capture::~Capture() {
  if (handle) {
    pcap_close(handle);
  }
}

bool Capture::init() {
  char errbuf[PCAP_ERRBUF_SIZE];

  std::string iface = cfg.interface;
  if (iface.empty()) {
    pcap_if_t *devs;
    if (pcap_findalldevs(&devs, errbuf) == -1) {
      std::cerr << "Error finding devices: " << errbuf << "\n";
      return false;
    }
    iface = devs->name;
    std::cout << "No interface specified, using: " << iface << "\n";
    pcap_freealldevs(devs);
  }

  handle = pcap_open_live(iface.c_str(), 65535, 1, 1000, errbuf);
  if (!handle) {
    std::cerr << "Failed to open interface " << iface << ": " << errbuf << "\n";
    return false;
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    std::cerr << "Interface is not Ethernet\n";
    return false;
  }

  return true;
}

void Capture::start() {
  std::cout << "Starting capture... (Ctrl+C to stop)\n";

  parser_thread = std::thread(&Capture::parser_loop, this);

  pcap_loop(handle, cfg.packet_count, packet_handler,
            reinterpret_cast<u_char *>(this));

  queue.stop();
  if (parser_thread.joinable()) {
    parser_thread.join();
  }

  if (queue.dropped() > 0) {
    std::cout << "Warning: dropped " << queue.dropped()
              << " packets (queue full)\n";
  }
}

void Capture::packet_handler(u_char *args, const struct pcap_pkthdr *header,
                             const u_char *packet) {
  Capture *cap = reinterpret_cast<Capture *>(args);
  cap->queue.push(header, packet);
}

void Capture::parser_loop() {
  RawPacket pkt;
  while (queue.pop(pkt)) {
    stats.total++;
    if (cfg.verbose) {
      std::cout << "Packet length: " << pkt.header.len << " bytes\n";
    }
    parse_ethernet(pkt.data.data(), pkt.header.caplen, cfg, stats);
  }
}
