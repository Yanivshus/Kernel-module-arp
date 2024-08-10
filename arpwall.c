#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/hashtable.h>

#define SPOOFED_ALERT -1
#define NOT_SPOOFED 1

DEFINE_HASHTABLE(arp_table, 8);//create hashtable to represnt the arp table, which will store ip->mac addreses.

//create an hashtable entry struct.
struct arp_entry{
    __be32 ip;
    unsigned char mac[ETH_ALEN];
    struct hlist_node node; // hashtable node.
};

static void add_arp_entry(__be32 ip, unsigned char *mac)
{
    struct arp_entry *entry;
    //iterate over buckets, to check if already exists an entry.
    hash_for_each_possible(arp_table, entry, node, ip)
    {
        //check if already exists
        if(entry->ip == ip){
            //update.
            memcpy(entry->mac, mac, ETH_ALEN);
            return;
        }
    }

    //allocate kernel space memory for entry if doesn't exists.
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if(!entry)
        return;
    
    //initiallize entry values.
    entry->ip = ip;
    memcpy(entry->mac, mac, ETH_ALEN);
    //add to table
    hash_add(arp_table, &entry->node, ip);
    //printk(KERN_INFO "Adding to hash table: %p\n", mac);
}



/// @brief check if there is already mac in the table -> means there is arp poisoning.
/// @param ip 
/// @param mac 
/// @return 
static int check_arp_spoofing(__be32 ip, unsigned char *mac)
{
    struct arp_entry* entry;
    int bkt;
    //iterate over buckets, to check for arp spoofing
    //there is an arp spoofing attack happening if the incoming arp response has the same mac has an already exists entry there is an arp spoofing attack.
    hash_for_each(arp_table, bkt, entry, node)
    {
        if(memcmp(entry->mac, mac, ETH_ALEN) == 0)
        {
            //printk(KERN_ALERT "Detected spoofing from mac: %s\n", mac);
            return SPOOFED_ALERT;          
        }
    }
    return NOT_SPOOFED;
}


//netfilter hook options -> will be configured in the init module.
static struct nf_hook_ops arp_nfho;

/// @brief function to hook to packet filtering before they arrive to target locally.
/// @param priv doesn't matter
/// @param skb socket buffer
/// @param state if hook stable
/// @return NF_ACCEPT - for routing the packet, NF_DROP - for throw to trash.
static unsigned int arp_hook_fnc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct ethhdr *eth;
    struct arphdr *arp;

    // if socket buffer is empty the packet will forwarded.
    if(!skb)
        return NF_ACCEPT;

    eth = eth_hdr(skb);
    
    if(eth->h_proto == htons(ETH_P_ARP)){
        arp = arp_hdr(skb);
        //after i detected and arp protocol packet, i will extract ip and mac addresses.
        unsigned char* arp_ptr = (unsigned char *)(arp + 1);
        unsigned char *src_mac = arp_ptr; // src ac
        __be32 src_ip = *(__be32 *)(arp_ptr + arp->ar_hln); // src ip
        arp_ptr += arp->ar_hln + arp->ar_pln;
        unsigned char *dst_mac = arp_ptr; // dst mac
        __be32 dst_ip = *(__be32 *)(arp_ptr + arp->ar_hln); // dst ips
        printk(KERN_INFO "Before checking Spoofing detetcted %s\n", src_mac); // need to remeber fix printing , computer crashes.
        if(ntohs(arp->ar_op) == ARPOP_REPLY)
        {
            if(check_arp_spoofing(src_ip, src_mac) == SPOOFED_ALERT)
            {
                //printk(KERN_WARNING "Detected Spoofing: IP %pI4 MAC %pM\n", src_ip, src_mac);
                return NF_DROP;
            }
            else{
                printk(KERN_ALERT "Regular Arp packet: hw_type=%u, proto_type=%u, op=%u\n",htons(arp->ar_hrd), htons(arp->ar_pro), htons(arp->ar_op));
            }
            add_arp_entry(src_ip, src_mac);
        }
    }
    return NF_ACCEPT;
}

// entry function for the arp monitor.
static int __init arp_mon_init(void)
{
    arp_nfho.hook = arp_hook_fnc; //my hooking function that monitors packets.
    arp_nfho.pf = NFPROTO_ARP; // define the protocol for packets, which is arp.
    arp_nfho.hooknum = NF_INET_PRE_ROUTING; // when received.
    arp_nfho.priority = NF_IP_PRI_FIRST; // be the first priority hook, the packet first will come through this hook.

    nf_register_net_hook(&init_net,&arp_nfho); // register the hook.
    printk(KERN_ALERT "Arpwall has been registerd!\n");   
    return 0; 
}


//unregister hook entry.
static void __exit arp_mon_exit(void)
{
    nf_unregister_net_hook(&init_net, &arp_nfho);// unregistering the hook to remove the arpwall.
    printk(KERN_ALERT "Removed the arpwall registery!\n");
}


module_init(arp_mon_init);
module_exit(arp_mon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yaniv Shusterman");
MODULE_DESCRIPTION("Arp spoofing attack prevention firewall");