#ifndef TRANSFER_H
#define TRANSFER_H
#include "global.h"

void send_messeg (struct net_device *dev,
                        uint32_t ttl, 
                        uint32_t ip_saddr, 
                        uint32_t ip_daddr, 
                        uint8_t* eth_daddr,
                        struct header_messager* header_in,
                        uint8_t* data, 
                        uint32_t size);

#endif