// airodump.cpp

#include <pcap.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <unistd.h>

#include <map>
#include <set>
#include <string>
#include <array>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

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
    // addr4 (WDS) and QoS control are deliberately not modeled here;
    // this program does not need to look past the body for those frames.
};

struct BeaconFixed
{
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capability;
};

#pragma pack(pop)

// Application state
using MacAddress = std::array<uint8_t, 6>;

struct APInfo
{
    int power = -100;
    int beacons = 0;
    int data = 0;
    int channel = 0;

    std::string encryption = "OPN";
    std::string essid = "<hidden>";
};

struct StationInfo
{
    int power = -100;
    int packets = 0;
    bool hasBssid = false;
    MacAddress bssid{};
    std::set<std::string> probedEssids;
};

static std::mutex g_tableMutex;
static std::map<MacAddress, APInfo> g_apList;
static std::map<MacAddress, StationInfo> g_stationList;

static std::atomic<bool> g_running{true};
static std::atomic<int> g_currentChannel{1};
static std::string g_iface;

// Small helpers
static MacAddress makeMac(const uint8_t* addr)
{
    MacAddress mac;
    for (int i = 0; i < 6; i++) mac[i] = addr[i];
    return mac;
}

static const MacAddress BROADCAST_MAC = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

static void formatMac(const MacAddress& mac, char* out /* at least 18 bytes */)
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static size_t alignOffset(size_t offset, size_t alignment)
{
    return (offset + alignment - 1) & ~(alignment - 1);
}

// Radiotap: extract antenna signal (dBm) -> PWR column
static int getPower(const uint8_t* packet, size_t caplen)
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

    // Fields must be walked in bit order (0..31); each field is only
    // present in the stream if its bit is set.
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
static std::string getEncryption(const BeaconFixed* beacon, const uint8_t* tag, const uint8_t* end)
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
static void parseSsidAndChannel(const uint8_t* tag, const uint8_t* end,
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

// Frame processors (caller already holds g_tableMutex)
static void processBeacon(const struct pcap_pkthdr* header, const uint8_t* packet,
                           const Dot11Hdr* dot11, const uint8_t* packetEnd)
{
    const BeaconFixed* beacon = reinterpret_cast<const BeaconFixed*>(dot11 + 1);
    if (reinterpret_cast<const uint8_t*>(beacon + 1) > packetEnd) return;

    const uint8_t* tag = reinterpret_cast<const uint8_t*>(beacon + 1);

    MacAddress bssid = makeMac(dot11->addr3);
    APInfo& ap = g_apList[bssid];

    ap.beacons++;

    int power = getPower(packet, header->caplen);
    if (power != -100) ap.power = power;

    ap.encryption = getEncryption(beacon, tag, packetEnd);
    parseSsidAndChannel(tag, packetEnd, ap.essid, &ap.channel);
}

static void processProbeRequest(const Dot11Hdr* dot11, const uint8_t* packetEnd)
{
    // Management fixed fields for a probe request are empty; tags start
    // immediately after the 24-byte MAC header.
    const uint8_t* tag = reinterpret_cast<const uint8_t*>(dot11 + 1);
    if (tag > packetEnd) return;

    MacAddress station = makeMac(dot11->addr2);
    StationInfo& st = g_stationList[station];
    st.packets++;

    std::string probed;
    parseSsidAndChannel(tag, packetEnd, probed, nullptr);
    if (!probed.empty() && probed != "<hidden>")
        st.probedEssids.insert(probed);
}

static void processData(const Dot11Hdr* dot11)
{
    uint16_t fc = dot11->fc;
    bool toDs   = (fc & 0x0100) != 0;
    bool fromDs = (fc & 0x0200) != 0;

    const uint8_t* bssidAddr = nullptr;
    const uint8_t* staAddr   = nullptr;

    if (!toDs && !fromDs)       { bssidAddr = dot11->addr3; staAddr = dot11->addr2; } // IBSS/adhoc
    else if (toDs && !fromDs)   { bssidAddr = dot11->addr1; staAddr = dot11->addr2; } // STA -> AP
    else if (!toDs && fromDs)   { bssidAddr = dot11->addr2; staAddr = dot11->addr1; } // AP -> STA
    else return; // WDS (toDs && fromDs): addr4 not modeled, skip

    MacAddress bssid = makeMac(bssidAddr);
    auto it = g_apList.find(bssid);
    if (it != g_apList.end()) it->second.data++;

    MacAddress sta = makeMac(staAddr);
    if (sta != BROADCAST_MAC)
    {
        StationInfo& st = g_stationList[sta];
        st.packets++;
        st.hasBssid = true;
        st.bssid = bssid;
    }
}


// Display
static void printAPList()
{
    // caller holds g_tableMutex
    printf("\033[2J\033[H");

    printf(" CH %2d ][ Elapsed: monitoring... ]\n\n", g_currentChannel.load());

    printf("%-18s %5s %8s %8s %4s %6s  %s\n",
        "BSSID", "PWR", "Beacons", "#Data", "CH", "ENC", "ESSID");
    printf("--------------------------------------------------------------------\n");

    char macStr[18];
    for (const auto& item : g_apList)
    {
        const APInfo& ap = item.second;
        formatMac(item.first, macStr);

        printf("%-18s %5d %8d %8d %4d %6s  %s\n",
            macStr, ap.power, ap.beacons, ap.data, ap.channel,
            ap.encryption.c_str(), ap.essid.c_str());
    }

    printf("\nBSSID              STATION            PWR   #Packets  PROBES\n");
    printf("--------------------------------------------------------------------\n");

    for (const auto& item : g_stationList)
    {
        const StationInfo& st = item.second;
        char staStr[18];
        formatMac(item.first, staStr);

        char bssidStr[18];
        if (st.hasBssid) formatMac(st.bssid, bssidStr);
        else snprintf(bssidStr, sizeof(bssidStr), "(not associated)");

        std::string probes;
        for (const auto& e : st.probedEssids)
        {
            if (!probes.empty()) probes += ",";
            probes += e;
        }

        printf("%-18s %-18s %5d %9d  %s\n",
            bssidStr, staStr, st.power, st.packets, probes.c_str());
    }

    fflush(stdout);
}

// Packet callback
static void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    (void)user;

    if (header->caplen < sizeof(RadiotapHdr)) return;

    const RadiotapHdr* radiotap = reinterpret_cast<const RadiotapHdr*>(packet);
    if (radiotap->it_len == 0 || radiotap->it_len > header->caplen) return;

    const uint8_t* packetEnd = packet + header->caplen;
    const Dot11Hdr* dot11 = reinterpret_cast<const Dot11Hdr*>(packet + radiotap->it_len);

    if (reinterpret_cast<const uint8_t*>(dot11 + 1) > packetEnd) return;

    uint16_t frameType = dot11->fc & 0x000C; // 0x00 = Management, 0x04 = Data

    std::lock_guard<std::mutex> lock(g_tableMutex);

    if ((dot11->fc & 0x00FC) == 0x0080)       // Management / Beacon
    {
        processBeacon(header, packet, dot11, packetEnd);
    }
    else if ((dot11->fc & 0x00FC) == 0x0040)  // Management / Probe Request
    {
        processProbeRequest(dot11, packetEnd);
    }
    else if (frameType == 0x0004)             // Data (incl. QoS Data subtypes)
    {
        processData(dot11);
    }
}

// Background threads: periodic redraw + channel hopping
static void refreshThread()
{
    while (g_running)
    {
        {
            std::lock_guard<std::mutex> lock(g_tableMutex);
            printAPList();
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

static void channelHopThread()
{
    const int channels[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
    const int nChannels = sizeof(channels) / sizeof(channels[0]);
    int idx = 0;

    while (g_running)
    {
        int ch = channels[idx];
        std::string cmd = "iw dev " + g_iface + " set channel " + std::to_string(ch) + " >/dev/null 2>&1";
        if (system(cmd.c_str()) != 0) { /* channel set failed; ignore and keep hopping */ }
        g_currentChannel = ch;

        idx = (idx + 1) % nChannels;
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
}

static pcap_t* g_handle = nullptr;

static void signalHandler(int)
{
    g_running = false;
    if (g_handle) pcap_breakloop(g_handle);
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("syntax : airodump <interface>\n");
        printf("sample : airodump mon0\n");
        return -1;
    }

    g_iface = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (g_handle == nullptr)
    {
        fprintf(stderr, "pcap_open_live failed : %s\n", errbuf);
        return -1;
    }

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    std::thread hopper(channelHopThread);
    std::thread refresher(refreshThread);

    pcap_loop(g_handle, 0, packetHandler, nullptr);

    g_running = false;
    if (hopper.joinable()) hopper.join();
    if (refresher.joinable()) refresher.join();

    pcap_close(g_handle);
    return 0;
}