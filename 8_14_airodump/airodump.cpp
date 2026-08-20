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
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

#include "dot11.h"

// Application state
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
