#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

//이더넷 2 출발지 목적지 타입
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];
    u_int8_t  ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type;                 
};

//ip 구조체 선언 (리틀인디안 기준)
struct libnet_ipv4_hdr {
    uint8_t  ip_hl:4;     
    uint8_t  ip_v:4;      
    uint8_t  ip_tos;       
    uint16_t ip_len;       
    uint16_t ip_id;       
    uint16_t ip_off;     
    uint8_t  ip_ttl;       
    uint8_t  ip_p;        
    uint16_t ip_sum;      
    struct in_addr ip_src, ip_dst;
};

//TCP 구조체 
struct libnet_tcp_hdr {
    u_int16_t th_sport;    
    u_int16_t th_dport;   
    u_int32_t th_seq;      
    u_int32_t th_ack;      
    u_int8_t  th_x2:4;     
    u_int8_t  th_off:4;    
    u_int8_t  th_flags;    
    u_int16_t th_win;      
    u_int16_t th_sum;      
    u_int16_t th_urp;      
};


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	// 랜카드 여는 부분(인터페이스 이름,최대 몇 바이트 , 무차별모드,타임아웃 , 에러 버퍼)
	// 실패시 NULL 반환 
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	// 패킷 받는 루프 
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue; //타임아웃 , 다시 시도 
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) { // 에러시 종
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
	
		struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet ;
		// ipv4인지 검사 
		if (ntohs(eth->ether_type) != 0x0800 ) continue;

		printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n" , 
				eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2] , 
			       	eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
		printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n", 
				eth ->ether_dhost[0] , eth->ether_dhost[1] , eth->ether_dhost[2],
				eth ->ether_dhost[3] , eth->ether_dhost[4] , eth ->ether_dhost[5] );

		//packet 포인터 이동(14)  ip 위치로 
		struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
		
		//TCP인지 검사 
		if (ip->ip_p != IPPROTO_TCP) continue;

		//inet_ntoa는 문자열 형식으로 돌려줌
		printf("src ip : %s\n" , inet_ntoa(ip->ip_src));
		printf("dst ip : %s\n" , inet_ntoa(ip->ip_dst));

		//ip 바이트 수 읽기 
		struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet +sizeof(struct libnet_ethernet_hdr)+ ip->ip_hl*4);
		//포트 순서 바꾸기 
		printf("src port :%d\n" , ntohs(tcp->th_sport));
		printf("dst port :%d\n" , ntohs(tcp->th_dport));



		// 시작 위치 
		const u_char* payload = packet  + sizeof(struct libnet_ethernet_hdr) + ip->ip_hl * 4 + tcp->th_off * 4;
		
		int payload_len = ntohs(ip->ip_len) - (ip->ip_hl*4) - (tcp->th_off*4);


		int len = payload_len;
		if (len > 20) len = 20 ; 

		printf("payload (len = %d): " , payload_len);
		for (int i=0 ; i< len; i++)
			printf("%02x" , payload[i]);
		printf("\n");
	}

	pcap_close(pcap);
}
