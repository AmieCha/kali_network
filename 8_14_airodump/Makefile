CXX      := g++
CXXFLAGS := -O2 -std=c++17 -Wall -Wextra -Iinclude
LDLIBS   := -lpcap -lpthread
TARGET   := airodump

.PHONY: all clean
all: $(TARGET)

SRCS := src/airodump.cpp src/dot11.cpp

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)