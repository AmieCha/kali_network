#include <pcap.h>
#include <cstdio>
#include "dot11hdr.h"

void packetHandler(u_char* user , const struct pcap_pkthdr* header , const u_char* packet )
{
    const  RadiotapHdr* radiotap = reinterpret_cast<const  RadiotapHdr*>(packet);
    const  Dot11Hdr* dot11 = reinterpret_cast<const  Dot11Hdr*>(packet + radiotap->it_len);
    
    // check beacon frame
    if ((dot11 -> fc & 0x00FC) == 0x0080)
    {
        // starting point of beacon fixed field  
        const BeaconFixed* beacon = reinterpret_cast<const BeaconFixed*>(dot11 + 1 );
        const uint8_t* tag = reinterpret_cast<const uint8_t*>(beacon + 1);
        const uint8_t* end = packet + header -> caplen ;

        printf("BSSID : %02X:%02X:%02X:%02X:%02X:%02X ", 
                dot11 -> addr2[0] , dot11-> addr2[1] , dot11->addr2[2],
                dot11 -> addr2[3] , dot11-> addr2[4] , dot11 -> addr2[5]);

        while (tag + 2 <= end )
        {
            uint8_t id = tag[0];
            uint8_t len = tag[1];

            if (tag + 2 + len > end ) break ;

            if (id ==0)
            {
                printf("%.*s" , len , tag + 2);
            }
            if (id == 3)
            {
                printf("ch %d " , tag[2]);
            }
            tag += 2 + len ;
        }
        printf("\n");
    }
}

int main(int argc, char* argv[] )
{
    if(argc != 2) 
    {
        printf("syntax : airdump <interface>\n ");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], 65536 ,1 , 1 , errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr , "pcap_open_live failed : %s\n" , errbuf );
        return -1;
    }

    pcap_loop(handle , 0 , packetHandler , nullptr);

    pcap_close(handle);
    return 0;
}