#include "nodes.h"
#include "global.h"
#include <linux/if_ether.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/jiffies.h>
#include "transfer.h"


struct node_info
{
    int id;
    struct list_head routes; 
    struct rhash_head node;
};

struct node_dev
{
    struct net_device *dev; 
    uint32_t ip_distr;
    uint32_t ip_source;
    uint8_t mac[ETH_ALEN];
    uint8_t distance;
    uint32_t update;
    struct list_head node;
};  

static struct rhashtable* clients = NULL;

static const struct rhashtable_params node_params = 
{
    .key_len = sizeof(int),   
    .key_offset = offsetof(struct node_info, id), 
    .head_offset = offsetof(struct node_info, node), 
    .automatic_shrinking = true, 
};

void client_update(struct net_device *dev,
                   int id,
                   uint32_t dev_ip, 
                   uint32_t ip, 
                   uint8_t* mac, 
                   uint8_t ttl_client)
{
    struct node_dev *dev_entry;
    struct node_dev *new_dev;
    int found = 0;
    
    rcu_read_lock();
    
    struct node_info *obj = rhashtable_lookup_fast(clients, &id, node_params);
    
    if (!obj) 
    {
        rcu_read_unlock();
        
        obj = kmalloc(sizeof(struct node_info), GFP_KERNEL);
        if (!obj)
            return;
        
        obj->id = id;
        INIT_LIST_HEAD(&obj->routes);
        
        new_dev = kmalloc(sizeof(struct node_dev), GFP_KERNEL);
        if (!new_dev) 
        {
            kfree(obj);
            return;
        }
        
        new_dev->dev = dev;  
        new_dev->ip_distr = dev_ip;
        new_dev->ip_source = ip;
        memcpy(new_dev->mac, mac, ETH_ALEN);
        new_dev->distance = ttl - ttl_client;  
        new_dev->update = jiffies;
        INIT_LIST_HEAD(&new_dev->node);
        
        list_add_tail(&new_dev->node, &obj->routes);
        
        if (rhashtable_insert_fast(clients, &obj->node, node_params)) 
        {
            list_del(&new_dev->node);
            kfree(new_dev);
            kfree(obj);
        } 
        else 
        {
            pr_info("add new client:%pI4 id:%d dist:%d\n", &ip, id, ttl - ttl_client);
        }
    } 
    else 
    {
        list_for_each_entry_rcu(dev_entry, &obj->routes, node) 
        {
            if (dev_entry->dev == dev)
            {  
                found = 1;
                if (dev_entry->distance >= (ttl - ttl_client))
                {
                    dev_entry->ip_distr = dev_ip;
                    dev_entry->ip_source = ip;
                    memcpy(dev_entry->mac, mac, ETH_ALEN);
                    dev_entry->distance = ttl - ttl_client;  
                    dev_entry->update = jiffies;
                    
                    pr_info("update network route:%pI4 id:%d dist:%d\n", &ip, id, ttl - ttl_client);
                }
                break;
            }
        }
        
        if (!found) 
        {
            new_dev = kmalloc(sizeof(struct node_dev), GFP_ATOMIC);
            if (new_dev) 
            {
                new_dev->dev = dev;  
                new_dev->ip_distr = dev_ip;
                new_dev->ip_source = ip;
                memcpy(new_dev->mac, mac, ETH_ALEN);
                new_dev->distance = ttl - ttl_client;  
                new_dev->update = jiffies;
                INIT_LIST_HEAD(&new_dev->node);
                
                list_add_tail_rcu(&new_dev->node, &obj->routes);
                pr_info("add network route:%pI4 id:%d dist:%d\n", &ip, id, ttl - ttl_client);
            }
        }
        
        rcu_read_unlock();
    }
}

void clients_send(uint32_t id, uint8_t* data, uint32_t size)
{
    struct node_info *obj;
    struct node_dev *dev_entry = NULL;
    struct node_dev *ptr;
    uint32_t min_dist;
     pr_info("clients_send start: %u  %*ph\n",
            id, (int)size, data);
    rcu_read_lock();
    
    obj = rhashtable_lookup_fast(clients, &id, node_params);
    if (!obj) {
        rcu_read_unlock();
        pr_warn("clients_send: client %u not found\n", id);
        return;
    }
    pr_info ("clients_send find id\n");
    min_dist = ttl;
    list_for_each_entry_rcu(ptr, &obj->routes, node) {
        if (ptr->distance < min_dist) {
            min_dist = ptr->distance;
            dev_entry = ptr;
        }
    }
    pr_info ("clients_send find round\n");
    if (!dev_entry) {
        rcu_read_unlock();
        pr_err("clients_send: no routes for id %u\n", id);
        return;
    }
    
    struct header_messager header;
    header.magic = htons(magic);
    header.type = 1;
    header.id = htonl(id);
    if (dev_entry)
    {
        pr_info("clients_send: saddr:%pI4 -> daddr:%pI4  %*ph\n",
                &dev_entry->ip_distr, &dev_entry->ip_source, (int)size, data);
    }
    else
    {
        pr_err("clients_send faile");
    }
    
    send_messeg(dev_entry->dev, ttl, dev_entry->ip_distr,
                dev_entry->ip_source, dev_entry->mac,
                &header, data, size);
    
    rcu_read_unlock();
}

void clients_init(void)
{
    clients_deinit();
    
    clients = kmalloc(sizeof(struct rhashtable), GFP_KERNEL);  
    if (!clients) 
    {
        return; 
    } 
    
    if (rhashtable_init(clients, &node_params)) 
    {
        kfree(clients);
        clients = NULL;
    }
}

void clients_deinit(void)
{
    if (!clients)
        return;
    
    struct rhashtable_iter iter;
    struct node_info *obj;
    struct node_dev *ptr, *tmp;
    
    rhashtable_walk_enter(clients, &iter);
    rhashtable_walk_start(&iter);
    
    while ((obj = rhashtable_walk_next(&iter)) != NULL) 
    {
        if (IS_ERR(obj)) 
        {
            if (PTR_ERR(obj) == -EAGAIN)
                continue;
            break;
        }
        
        list_for_each_entry_safe(ptr, tmp, &obj->routes, node) 
        {
            list_del_rcu(&ptr->node);
            kfree(ptr);
        }
        
        if (rhashtable_remove_fast(clients, &obj->node, node_params)) 
        {
            pr_err("Failed to remove object (id=%d)\n", obj->id);
        } 
        else 
        {
            kfree(obj);
        }
    }
    
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);
    
    rhashtable_destroy(clients);  
    kfree(clients);
    clients = NULL;
}

uint32_t client_get_count (void)
{
    if (!clients)
        return 0;
    return atomic_read(&clients->nelems);
}

uint32_t client_request_list (struct client_info* info, uint32_t max_client)
{
    if (!clients)
        return 0;
        
    uint32_t max_count = atomic_read(&clients->nelems);
    if (max_count > max_client)
        max_count = max_client;
    
    struct rhashtable_iter iter;  // Объявление здесь
    struct node_info *obj;
    struct node_dev *ptr;
    uint32_t count = 0;
    
    rhashtable_walk_enter(clients, &iter);
    rhashtable_walk_start(&iter);
    
    while (count < max_count && (obj = rhashtable_walk_next(&iter)) != NULL) 
    {
        if (IS_ERR(obj)) 
        {
            if (PTR_ERR(obj) == -EAGAIN)
                continue;
            break;
        }
        
        uint32_t min_dist = ttl;
        uint32_t min_update = 0;
        
        list_for_each_entry(ptr, &obj->routes, node) 
        {
            if (ptr->distance < min_dist)
            {
                min_dist = ptr->distance;
                min_update = ptr->update;
            }
        }
        
        if (min_dist != ttl) 
        {
            info[count].dist = min_dist;
            info[count].update = min_update;
        }
        info[count].id = obj->id;
        count++;
    }
    
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    return count;
}


