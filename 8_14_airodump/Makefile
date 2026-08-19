CXX      := g++
CXXFLAGS := -O2 -std=c++17 -Wall -Wextra
LDLIBS   := -lpcap -lpthread
TARGET   := airodump

.PHONY: all clean
all: $(TARGET)

$(TARGET): airodump.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)