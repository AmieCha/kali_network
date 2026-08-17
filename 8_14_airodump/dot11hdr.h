#pragma once 
#include <cstdint>

#pragma pack(push , 1)

struct RadiotapHdr final{
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
};

struct Dot11Hdr {
    uint16_t fc; //frame control
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
};

struct BeaconFixed final {
    uint8_t timestamp[8];
    uint16_t interval;
    uint16_t capability;
}

#pragma pack(pop)

