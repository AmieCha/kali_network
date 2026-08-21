// dot11.h
// Radiotap / 802.11 wire structures and parsing helpers shared by airodump.cpp
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <array>

// Wire structures
#pragma pack(push, 1)

struct RadiotapHdr
{
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;      // total length of the radiotap header
    uint32_t it_present;  // bitmap of which fields follow
};

struct Dot11Hdr
{
    uint16_t fc;       // frame control
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq;
};

struct BeaconFixed
{
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capability;
};

#pragma pack(pop)

using MacAddress = std::array<uint8_t, 6>;

extern const MacAddress BROADCAST_MAC;

// Helpers (implemented in dot11.cpp)
void formatMac(const MacAddress& mac, char* out /* at least 18 bytes */);

size_t alignOffset(size_t offset, size_t alignment);

MacAddress makeMac(const uint8_t* addr);

// Radiotap: extract antenna signal (dBm) -> PWR column
int getPower(const uint8_t* packet, size_t caplen);

// Encryption detection from beacon information elements
std::string getEncryption(const BeaconFixed* beacon, const uint8_t* tag, const uint8_t* end);

// Shared IE (tagged parameter) walk: pulls out SSID + DS channel
void parseSsidAndChannel(const uint8_t* tag, const uint8_t* end,
                          std::string& essid, int* channelOut);
