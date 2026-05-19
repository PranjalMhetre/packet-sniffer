# Packet Sniffer

A network packet analyzer written in C++ that captures and parses live traffic at the binary level. Built on libpcap with a multithreaded producer-consumer architecture. A capture thread pushes raw packets into a thread-safe queue while a parser thread decodes Ethernet, IP, TCP, UDP, DNS, and HTTP headers in parallel.

## Features

- Protocol parsing: Ethernet to IP to TCP/UDP to HTTP/DNS parsing chain using struct overlays on raw memory
- Connection tracking: 5-tuple flow table (src IP, dst IP, src port, dst port, protocol) with TCP state machine (SYN_SENT to ESTABLISHED to CLOSING to RESET)
- Multithreaded capture: producer-consumer model with a thread-safe queue prevents packet loss under high traffic
- DNS reconstruction: parses binary DNS label format and resolves compressed domain names from live queries and responses
- HTTP inspection: reconstructs plaintext HTTP/1.1 requests and responses from TCP payloads on port 80
- CLI filtering: filter by host IP (-h), port (-p), interface (-i), and packet count (-n)
- Session summary: prints protocol breakdown, top hosts by packet count, and ranked connection table on exit

## Build

**Dependencies:**
```bash
sudo apt-get install libpcap-dev   # Ubuntu/Debian
brew install libpcap               # macOS
```

**Compile:**
```bash
make
```

**Clean:**
```bash
make clean
```

## Usage

Requires root/sudo to open a raw socket.

```bash
sudo ./sniffer [options]
```

| Flag | Description | Example |
|------|-------------|---------|
| `-i` | Network interface to capture on | `-i eth0` |
| `-h` | Filter by host IP address | `-h 192.168.1.1` |
| `-p` | Filter by port number | `-p 80` |
| `-n` | Stop after N packets | `-n 100` |
| `-v` | Verbose mode, print full header details | `-v` |

**Examples:**

```bash
# Capture all traffic with full header output
sudo ./sniffer -v

# Capture only HTTP traffic
sudo ./sniffer -v -p 80

# Capture traffic to/from a specific host
sudo ./sniffer -h 8.8.8.8

# Capture 50 packets on a specific interface
sudo ./sniffer -i eth0 -n 50 -v
```

## Example Output

```
=== Packet Sniffer ===
======================

No interface specified, using: eth0
Starting capture... (Ctrl+C to stop)
Packet length: 93 bytes
ETH  00:15:5d:4a:f8:3a -> 00:15:5d:64:f4:c4  type=0x0800
IP   172.31.185.120  -> 8.8.8.8          proto=17  ttl=64  len=79
UDP  172.31.185.120 -> 8.8.8.8
DNS  QUERY  A     google.com
Packet length: 97 bytes
ETH  00:15:5d:64:f4:c4 -> 00:15:5d:4a:f8:3a  type=0x0800
IP   8.8.8.8         -> 172.31.185.120   proto=17  ttl=122  len=83
UDP  8.8.8.8 -> 172.31.185.120
DNS  REPLY  A     google.com -> 142.250.190.238  ttl=300s
Packet length: 93 bytes
ETH  00:15:5d:4a:f8:3a -> 00:15:5d:64:f4:c4  type=0x0800
IP   172.31.185.120  -> 8.8.8.8          proto=17  ttl=64  len=79
UDP  172.31.185.120 -> 8.8.8.8
DNS  QUERY  A     github.com
Packet length: 97 bytes
ETH  00:15:5d:64:f4:c4 -> 00:15:5d:4a:f8:3a  type=0x0800
IP   8.8.8.8         -> 172.31.185.120   proto=17  ttl=122  len=83
UDP  8.8.8.8 -> 172.31.185.120
DNS  REPLY  A     github.com -> 140.82.112.4  ttl=60s
Packet length: 94 bytes
ETH  00:15:5d:4a:f8:3a -> 00:15:5d:64:f4:c4  type=0x0800
IP   172.31.185.120  -> 8.8.8.8          proto=17  ttl=64  len=80
UDP  172.31.185.120 -> 8.8.8.8
DNS  QUERY  A     youtube.com
Packet length: 98 bytes
ETH  00:15:5d:64:f4:c4 -> 00:15:5d:4a:f8:3a  type=0x0800
IP   8.8.8.8         -> 172.31.185.120   proto=17  ttl=123  len=84
UDP  8.8.8.8 -> 172.31.185.120
DNS  REPLY  A     youtube.com -> 142.251.211.174  ttl=300s
Packet length: 140 bytes
ETH  00:15:5d:4a:f8:3a -> 00:15:5d:64:f4:c4  type=0x0800
IP   172.31.185.120  -> 172.66.147.243   proto=6  ttl=64  len=126
TCP  172.31.185.120:38642 -> 172.66.147.243:80     [ACK PSH]  seq=2810497607
     HTTP: GET / HTTP/1.1
     Host: example.com
Packet length: 903 bytes
ETH  00:15:5d:64:f4:c4 -> 00:15:5d:4a:f8:3a  type=0x0800
IP   172.66.147.243  -> 172.31.185.120   proto=6  ttl=58  len=889
TCP  172.66.147.243:80    -> 172.31.185.120:38642  [ACK PSH]  seq=496224992
     HTTP: HTTP/1.1 200 OK
^C
Capture stopped.

=== Session Summary ===
Total packets : 1093
TCP           : 1063
UDP           : 23
ARP           : 4
ICMP          : 0
HTTP          : 2
DNS           : 6
Unique hosts  : 24

Top hosts:
  172.31.185.120     1083 packets
  20.189.173.5       256 packets
  13.78.111.199      155 packets
  140.82.114.21      140 packets
  140.82.112.6       76 packets

=== Connection Table ===
Source                 Destination            Proto  Packets Bytes
---------------------------------------------------------------------------
172.31.185.120:54284   20.189.173.5:443       TCP    199     247 KB       ESTABLISHED
13.107.246.40:443      172.31.185.120:50948   TCP    36      22 KB        ESTABLISHED
13.89.179.10:443       172.31.185.120:51714   TCP    35      26 KB        CLOSING
172.31.185.120:57078   172.64.155.209:443     TCP    34      40 KB        ESTABLISHED
140.82.113.22:443      172.31.185.120:33258   TCP    31      29 KB        RESET
140.82.113.22:443      172.31.185.120:33256   TCP    31      36 KB        ESTABLISHED
13.78.111.199:443      172.31.185.120:47918   TCP    30      19 KB        CLOSING
140.82.112.6:443       172.31.185.120:43982   TCP    29      86 KB        RESET
172.31.185.120:53250   20.42.65.85:443        TCP    27      12 KB        CLOSING
140.82.114.21:443      172.31.185.120:58818   TCP    25      9 KB         ESTABLISHED
========================
======================
```

## Architecture

```
Capture Thread
  libpcap -> packet_handler() -> PacketQueue.push()
       |
       | thread-safe queue (mutex + condition variable)
       |
Parser Thread
  PacketQueue.pop() -> parse_ethernet()
       -> parse_ip()
            -> parse_tcp() -> try_parse_http()
            -> parse_udp() -> parse_dns()
       |
Stats + ConnectionTable
  Protocol counters, host map, 5-tuple flow tracking
```

**Parsing chain:** Each layer casts the raw byte buffer to a packed struct using reinterpret_cast, reads fields with network-to-host byte order conversion (ntohs/ntohl), then advances the pointer past the header and calls the next layer's parser.

**Connection tracking:** Uses std::unordered_map with a custom hash over the 5-tuple. Connections are normalized (lower IP first) so packets in both directions map to the same entry. TCP state is tracked via flag bitmasks on each packet.

**Thread safety:** The PacketQueue protects its internal std::queue with a std::mutex and uses a std::condition_variable to block the parser thread when the queue is empty rather than busy-waiting.

## Project Structure

```
packet-sniffer/
├── src/
│   ├── main.cpp
│   ├── cli.h / cli.cpp
│   ├── capture.h / capture.cpp
│   ├── packet_queue.h / packet_queue.cpp
│   ├── ethernet.h / ethernet.cpp
│   ├── ip.h / ip.cpp
│   ├── tcp.h / tcp.cpp
│   ├── dns.h / dns.cpp
│   ├── connection.h / connection.cpp
│   └── stats.h
└── Makefile
```

## Technical Concepts

- Binary protocol parsing: struct overlay (reinterpret_cast) on raw memory with __attribute__((packed)) to prevent compiler padding
- Network byte order: all multi-byte fields converted with ntohs/ntohl (big-endian wire format vs little-endian x86)
- Bitmask operations: IHL extraction (& 0x0F), TCP data offset (>> 4), flag decoding
- DNS compression pointers: label format parsing with pointer jump resolution and loop detection
- Producer-consumer concurrency: std::mutex, std::condition_variable, std::thread
- Custom hash functions: std::unordered_map with a hand-rolled hash combining all 5-tuple fields via XOR

## Notes

- HTTPS traffic (port 443) is encrypted, so TCP connections are tracked but payload content is not readable
- DNS parsing requires queries to bypass the local resolver (e.g. dig google.com @8.8.8.8)
- Tested on Ubuntu 24.04 / WSL2 with libpcap 1.10
