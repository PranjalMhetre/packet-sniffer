#pragma once
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <pcap.h>
#include <queue>
#include <vector>

struct RawPacket {
  std::vector<uint8_t> data;
  struct pcap_pkthdr header;
};

class PacketQueue {
public:
  PacketQueue(size_t max_size = 10000);

  bool push(const struct pcap_pkthdr *header, const u_char *data);
  bool pop(RawPacket &out);
  void stop();

  int dropped() const { return dropped_count; }

private:
  std::queue<RawPacket> queue;
  std::mutex mtx;
  std::condition_variable cv;
  size_t max_size;
  bool stopped = false;
  int dropped_count = 0;
};
