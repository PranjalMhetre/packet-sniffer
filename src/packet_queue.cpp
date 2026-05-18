#include "packet_queue.h"

PacketQueue::PacketQueue(size_t max_size) : max_size(max_size) {}

bool PacketQueue::push(const struct pcap_pkthdr *header, const u_char *data) {
  std::lock_guard<std::mutex> lock(mtx);

  if (queue.size() >= max_size) {
    dropped_count++;
    return false;
  }

  // libpcap reuses its internal buffer after the callback returns
  RawPacket pkt;
  pkt.header = *header;
  pkt.data.assign(data, data + header->caplen);
  queue.push(std::move(pkt));

  cv.notify_one();
  return true;
}

bool PacketQueue::pop(RawPacket &out) {
  std::unique_lock<std::mutex> lock(mtx);

  cv.wait(lock, [this] { return !queue.empty() || stopped; });

  if (queue.empty()) {
    return false;
  }

  out = std::move(queue.front());
  queue.pop();
  return true;
}

void PacketQueue::stop() {
  std::lock_guard<std::mutex> lock(mtx);
  stopped = true;
  cv.notify_all();
}
