#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h> 
#include <linux/in.h>  
#include <linux/uuid.h>
#include <linux/timer.h>


struct task_data 
{
    struct tasklet_struct tasklet;
    struct sk_buff *skb;
};

struct device_info 
{
    struct net_device *dev;            
    uint32_t ip;
    uint32_t broadcast;   
    struct list_head node;  
};

#pragma pack(push, 1)
struct header_messager 
{
    uint16_t magic;
    uint32_t id;
    uint8_t type;
};
#pragma pack(pop)

LIST_HEAD(list_dev);

static struct nf_hook_ops inputHook;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kormi Ka");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("0.01");
static int max_size = 32; 
static const int ttl = 10; 
static const int port = 9977; 
static const uint16_t magic = 0xFACB;
static uint32_t id = 1243464;  
static struct timer_list timer;
static const uint8_t eth_broacast[ETH_ALEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};


module_param(max_size, int, 0644);
MODULE_PARM_DESC(my_int, "Max size out packet");

void send_func (unsigned long d)
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



static unsigned int input_hook (void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;
    
    struct ethhdr *eth_in = eth_hdr(skb);    
    struct udphdr *udp_in = udp_hdr(skb);
    pr_info("get udp from ip:%pI4 mac %*ph:\n", &iph->saddr, sizeof(eth_in->h_source),eth_in->h_source);
    
    if (udp_in->dest != htons(port))
        return NF_ACCEPT;
    
    struct header_messager* header = (struct header_messager*)(udp_in + 1);

    if (header->magic != htons(magic))
        return NF_ACCEPT;
    
    if (header->type == 0)
    {
        struct device_info* info;
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
        }
        pr_info("get hello messeger from ip:%pI4 id:%d\n", &iph->saddr, ntohl(header->id));
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
    printk(KERN_INFO "Hello, World!\n");
    struct net_device *dev;
    struct net *net = &init_net;
    int count = 0;

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
    timer_setup(&timer, timer_callback, 0);
    timer.expires = jiffies + msecs_to_jiffies(10000); 
    add_timer(&timer);

    
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
    del_timer(&timer);
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(init);
module_exit(exit);