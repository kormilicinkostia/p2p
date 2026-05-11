#ifndef NODES_H
#define NODES_H
#include <linux/rhashtable.h>


typedef struct rhashtable clients_struct ;
void clients_init(void);
void clients_deinit (void);

void client_update(struct net_device *dev,
                   int id,
                   uint32_t dev_ip,
                   uint32_t ip, 
                   uint8_t* mac, 
                   uint8_t ttl_client);
struct client_info
{
    uint32_t id;
    uint32_t dist;
    uint32_t update;
};

uint32_t client_request_list (struct client_info* info, uint32_t mmax_clientax_user);
void clients_send(uint32_t id, uint8_t* data, uint32_t size);
uint32_t client_get_count (void);




#endif