#include <linux/module.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "transfer.h"
#include "global.h"

struct task_data 
{
    struct tasklet_struct tasklet;
    struct sk_buff *skb;
};

static void send_func (unsigned long d)
{
    struct task_data *data = (struct task_data *)d;
    struct sk_buff* skb = data->skb;

    if (dev_queue_xmit(skb) != 0) 
    {
        pr_err("dev_queue_xmit failed\n");
        kfree_skb(skb);
    }
    kfree (data);
}

void send_messeg (struct net_device *dev,
                        uint32_t ttl, 
                        uint32_t ip_saddr, 
                        uint32_t ip_daddr, 
                        uint8_t* eth_daddr,
                        struct header_messager* header_in,
                        uint8_t* data, 
                        uint32_t size)
{
    pr_info("start send_messeg\n");
    int packet_size = sizeof(struct ethhdr) 
                    + sizeof(struct iphdr) 
                    + sizeof(struct udphdr)
                    + sizeof(struct header_messager)
                    + size;
    
    int hh_len = LL_RESERVED_SPACE(dev);
    int tlen = dev->needed_tailroom;
    struct sk_buff* skb = netdev_alloc_skb(dev, hh_len + tlen + packet_size);

    if (!skb) 
    {
        pr_err("netdev_alloc_skb failed\n");
        return;
    }

    skb_reserve(skb, hh_len);
    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);
    skb_put(skb, packet_size);
    skb_reset_network_header(skb);
    skb_set_transport_header(skb, sizeof(struct iphdr));
    
    struct iphdr* ip_out = ip_hdr(skb);
    ip_out->version = 4;
    ip_out->ihl = 5;
    ip_out->tos = 0;
    ip_out->tot_len = htons(packet_size - sizeof(struct ethhdr));
    ip_out->id = 0;
    ip_out->frag_off = htons(0x4000);
    ip_out->ttl = ttl;
    ip_out->protocol = IPPROTO_UDP;
    ip_out->saddr = ip_saddr;
    ip_out->daddr = ip_daddr;
    ip_out->check = 0;
    ip_out->check = ip_fast_csum((u8 *)ip_out, ip_out->ihl);

    struct udphdr* udp_out = udp_hdr(skb);

    udp_out->source = htons(port);
    udp_out->dest = htons(port);
    udp_out->len = htons(sizeof(struct udphdr)+ sizeof(struct header_messager) + size);
    udp_out->check = 0;
    struct header_messager* header_out = (struct header_messager*)(udp_out + 1);
    memcpy (header_out, header_in, sizeof (struct header_messager));

    if (size > 0 && data)
    {
        uint8_t* data_out = (uint8_t*)(header_out + 1);
        memcpy (data_out, data, size);
    }
    
    skb_push(skb, sizeof(struct ethhdr));
    skb_reset_mac_header(skb);
    
    struct ethhdr *eth_out = eth_hdr(skb);
    memset(eth_out, 0, sizeof(struct ethhdr));
    memcpy(eth_out->h_source, dev->dev_addr , ETH_ALEN);
    memcpy(eth_out->h_dest, eth_daddr, ETH_ALEN);
    eth_out->h_proto = htons(ETH_P_IP);

    struct task_data *task = kmalloc(sizeof(struct task_data), GFP_KERNEL);
    if (!task)
    {
        kfree_skb(skb);
        return;
    }
    task->skb = skb;
    tasklet_init(&task->tasklet, send_func, (unsigned long)task);
    tasklet_schedule(&task->tasklet);
    pr_info("end send_messeg\n");
}
