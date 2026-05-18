CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
LIBS = -lpcap -lpthread
SRC_DIR = src
SRCS = $(SRC_DIR)/main.cpp \
       $(SRC_DIR)/capture.cpp \
       $(SRC_DIR)/ethernet.cpp \
       $(SRC_DIR)/ip.cpp \
       $(SRC_DIR)/tcp.cpp \
       $(SRC_DIR)/dns.cpp \
       $(SRC_DIR)/connection.cpp \
       $(SRC_DIR)/packet_queue.cpp \
       $(SRC_DIR)/cli.cpp
TARGET = sniffer

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)
