// dot11.h
// Radiotap / 802.11 wire structures and parsing helpers shared by airodump.cpp
#pragma once

#include <cstdint>
#include <cstdio>
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

static const MacAddress BROADCAST_MAC = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

// Small helpers
inline MacAddress makeMac(const uint8_t* addr)
{
    MacAddress mac;
    for (int i = 0; i < 6; i++) mac[i] = addr[i];
    return mac;
}

inline void formatMac(const MacAddress& mac, char* out /* at least 18 bytes */)
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

inline size_t alignOffset(size_t offset, size_t alignment)
{
    return (offset + alignment - 1) & ~(alignment - 1);
}

// Radiotap: extract antenna signal (dBm) -> PWR column
inline int getPower(const uint8_t* packet, size_t caplen)
{
    if (caplen < sizeof(RadiotapHdr)) return -100;

    const RadiotapHdr* radiotap = reinterpret_cast<const RadiotapHdr*>(packet);
    uint32_t present = radiotap->it_present;
    size_t offset = sizeof(RadiotapHdr); // fields start right after the fixed 8-byte header

    // Radiotap allows chained "present" words when bit 31 (extended) is set.
    while (present & (1u << 31))
    {
        if (offset + 4 > caplen) return -100;
        present = *reinterpret_cast<const uint32_t*>(packet + offset);
        offset += 4;
    }

    if (present & (1u << 0)) // TSFT (8 bytes, 8-byte aligned)
    {
        offset = alignOffset(offset, 8);
        offset += 8;
    }
    if (present & (1u << 1)) // Flags (1 byte)
    {
        offset += 1;
    }
    if (present & (1u << 2)) // Rate (1 byte)
    {
        offset += 1;
    }
    if (present & (1u << 3)) // Channel (freq u16 + flags u16, 2-byte aligned)
    {
        offset = alignOffset(offset, 2);
        offset += 4;
    }
    if (present & (1u << 4)) // FHSS (2 bytes)
    {
        offset += 2;
    }
    if (present & (1u << 5)) // Antenna Signal (1 byte, signed dBm)
    {
        if (offset >= caplen) return -100;
        return static_cast<int>(*reinterpret_cast<const int8_t*>(packet + offset));
    }

    return -100;
}

// Encryption detection from beacon information elements
inline std::string getEncryption(const BeaconFixed* beacon, const uint8_t* tag, const uint8_t* end)
{
    // Privacy bit not set -> open network
    if ((beacon->capability & 0x0010) == 0)
        return "OPN";

    bool hasRSN = false; // -> WPA2 (or WPA3, not distinguished here)
    bool hasWPA = false; // -> WPA (vendor specific IE)

    const uint8_t* current = tag;

    while (current + 2 <= end)
    {
        uint8_t id  = current[0];
        uint8_t len = current[1];

        if (current + 2 + len > end) break;

        if (id == 48) hasRSN = true; // RSN Information Element

        if (id == 221 && len >= 4)   // Vendor Specific
        {
            if (current[2] == 0x00 && current[3] == 0x50 &&
                current[4] == 0xF2 && current[5] == 0x01)
            {
                hasWPA = true;
            }
        }

        current += 2 + len;
    }

    if (hasRSN) return "WPA2";
    if (hasWPA) return "WPA";
    return "WEP"; // privacy bit set, but no RSN/WPA IE -> legacy WEP
}

// Shared IE (tagged parameter) walk: pulls out SSID + DS channel
inline void parseSsidAndChannel(const uint8_t* tag, const uint8_t* end,
                                 std::string& essid, int* channelOut)
{
    while (tag + 2 <= end)
    {
        uint8_t id  = tag[0];
        uint8_t len = tag[1];

        if (tag + 2 + len > end) break;

        if (id == 0) // SSID
        {
            if (len == 0)
                essid = "<hidden>";
            else
                essid.assign(reinterpret_cast<const char*>(tag + 2), len);
        }
        else if (id == 3 && len >= 1 && channelOut) // DS Parameter Set
        {
            *channelOut = tag[2];
        }

        tag += 2 + len;
    }
}
