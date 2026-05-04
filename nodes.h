#ifndef NODES_H
#define NODES_H
#include <linux/rhashtable.h>


typedef struct rhashtable clients_struct ;
void clients_init(void);
void clients_deinit (void);

void client_update(struct net_device *dev,
                   int id, 
                   uint32_t ip, 
                   uint8_t* mac, 
                   uint8_t ttl_client);


#endif