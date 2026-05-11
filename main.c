#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h> 
#include <linux/in.h>  
#include <linux/timer.h>
#include <linux/random.h>
#include "transfer.h"
#include "global.h"
#include "nodes.h"
#include "dev.h"

struct device_info 
{
    struct net_device *dev;            
    uint32_t ip;
    uint32_t broadcast;
    struct list_head node;  
};


LIST_HEAD(list_dev);

static struct nf_hook_ops inputHook;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kormi Ka");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("0.01");
static int max_size = 32; 
const int ttl = 10; 
const int port = 9977; 
const uint16_t magic = 0xFACB;
static uint32_t id;  
static struct timer_list timer;
static const uint8_t eth_broacast[ETH_ALEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};


module_param(max_size, int, 0644);
MODULE_PARM_DESC(my_int, "Max size out packet");


static unsigned int input_hook (void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;
    
    struct ethhdr *eth_in = eth_hdr(skb);    
    struct udphdr *udp_in = udp_hdr(skb);
    //pr_info("get udp from ip:%pI4 mac %*ph:\n", &iph->saddr, sizeof(eth_in->h_source),eth_in->h_source);
    
    if (udp_in->dest != htons(port))
        return NF_ACCEPT;
    
    struct header_messager* header = (struct header_messager*)(udp_in + 1);

    if (header->magic != htons(magic))
        return NF_ACCEPT;
    
    if (header->type == 0)
    {
        struct device_info* info;
        uint32_t ip;
        list_for_each_entry(info, &list_dev, node) 
        {
            if (info->dev != skb->dev)
            {
                send_messeg (info->dev, 
                            iph->ttl - 1,
                            info->ip, 
                            info->broadcast, 
                            eth_broacast,
                            header, 
                            NULL,
                            0);
                printk("Replase Hello Messeger device name: %s, ip:%pI4 broadcat:%pI4\n", info->dev->name, &info->ip, &info->broadcast); 
            }
            else
            {
                ip = info->ip;
            }
        }
        client_update (skb->dev,
                   ntohl(header->id),
                   ip, 
                   iph->saddr, 
                   eth_in->h_source, 
                   iph->ttl - 1);
        pr_info("get hello messeger from ip:%pI4 id:%d\n", &iph->saddr, ntohl(header->id));
    }
    if (header->type == 1)
    {
        uint8_t* data_in = (uint8_t*)(header + 1);
        uint32_t size = ntohs(udp_in->len) - sizeof(struct udphdr) -  sizeof(struct header_messager);

        if (header->id == htonl(id))
        {
            pr_info("Data netvork: %*ph\n", (int)size, data_in);
            dev_send (data_in, size);
        }
        else
        {
            pr_info("Replase netvork: %*ph\n", (int)size, data_in);
            clients_send(header->id , data_in, size);
        }
    }
    return NF_ACCEPT;
}
struct header_messager header_global;
static void send_greetings (void)
{
    struct device_info* info;
    list_for_each_entry(info, &list_dev, node) 
    {        
        struct header_messager header;
        header.magic = htons(magic);
        header.type = 0;
        header.id = htonl(id);
        send_messeg (info->dev, 
                    ttl,
                    info->ip, 
                    info->broadcast, 
                    eth_broacast,
                    &header, 
                    NULL,
                    0);

        pr_info("Send Hello Messeger device name: %s, ip:%pI4 broadcat:%pI4\n", info->dev->name, &info->ip, &info->broadcast);

    }

}

void timer_callback(struct timer_list *t) 
{
    send_greetings ();
    mod_timer(t, jiffies + msecs_to_jiffies(10000));
}

static int __init init (void) 
{
    inputHook.hook = input_hook;
    inputHook.hooknum = NF_INET_LOCAL_IN;
    inputHook.pf = PF_INET;
    inputHook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &inputHook);
    
    struct net_device *dev;
    struct net *net = &init_net;
    int count = 0;
    id = get_random_u32();
    printk(KERN_INFO "Hello, World! %u\n", id);
    rcu_read_lock();

    /* Обход всех сетевых интерфейсов в пространстве имен */
    for_each_netdev_rcu(net, dev) 
    {
        if (dev->type != 1 || dev->state != 3)
            continue;  
        struct in_device *in_dev = __in_dev_get_rcu(dev);
        if (!in_dev) 
            continue;

        struct in_ifaddr *ifa = rcu_dereference(in_dev->ifa_list);
        if (!ifa)
            continue;

        if (ifa->ifa_address == 0 || ifa->ifa_broadcast == 0)
            continue;

        struct device_info* info = kmalloc(sizeof(struct device_info), GFP_KERNEL);    
        if (!info) 
            continue;

        INIT_LIST_HEAD(&info->node);
        
        info->dev = dev;
        info->ip = ifa->ifa_address;
        info->broadcast = ifa->ifa_broadcast;

        list_add_tail(&info->node, &list_dev);

    }
    rcu_read_unlock();
    send_greetings ();
    clients_init ();
    timer_setup(&timer, timer_callback, 0);
    timer.expires = jiffies + msecs_to_jiffies(10000); 
    add_timer(&timer);
    dev_init ();
    return 0;
}

static void __exit exit (void) 
{
    nf_unregister_net_hook(&init_net, &inputHook);

    struct device_info *ptr, *tmp;

    list_for_each_entry_safe(ptr, tmp, &list_dev, node) 
    {
        list_del(&ptr->node);
        kfree(ptr);
    }
    clients_deinit ();
    del_timer(&timer);
    dev_deinit ();
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(init);
module_exit(exit);