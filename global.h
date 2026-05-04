#ifndef GLOBAL_H
#define GLOBAL_H

#pragma pack(push, 1)
struct header_messager 
{
    uint16_t magic;
    uint32_t id;
    uint8_t type;
};
#pragma pack(pop)

extern const int port;
extern const int ttl; 

#endif