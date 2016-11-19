#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

static struct nf_hook_ops nfho;         //struct holding set of hook function options
static struct nf_hook_ops nfho_out; 
int i;
int j;
//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); //you can access to IP source and dest - ip_header->saddr, ip_header->daddr
if (ip_header->protocol == 1){    
  if ((ip_header->saddr == in_aton("192.168.213.130")) || (ip_header->saddr == in_aton("192.168.213.131")) || (ip_header->saddr == in_aton("192.168.213.132"))) 
  {
    printk(KERN_INFO "Customized Module Triggerred (IN): ");
    printk(KERN_INFO "Protocol: %u\n", ip_header->protocol);
    printk(KERN_INFO "Source IP: %u\n", ip_header->saddr);
    printk(KERN_INFO "Dest IP: %u\n", ip_header->daddr);
    i+=1;
    printk(KERN_INFO "Income Packet Amount %u\n", i);
  }}
  //return NF_DROP;
  return NF_ACCEPT;  //accept the packet
}

unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
  if (ip_header->protocol == 1){ 
  if ((ip_header->daddr == in_aton("192.168.213.130")) || (ip_header->daddr == in_aton("192.168.213.131")) || (ip_header->daddr == in_aton("192.168.213.132"))) 
  {
    printk(KERN_INFO "Customized Module Triggerred (OUT): ");
    printk(KERN_INFO "Protocol: %u\n", ip_header->protocol);
    printk(KERN_INFO "Source IP: %u\n", ip_header->saddr);
    printk(KERN_INFO "Dest IP: %u\n", ip_header->daddr);
    j+=1;
    printk(KERN_INFO "Outcome Packet Amount %u\n", j);
}
  return NF_ACCEPT; 
}}


//Called when module loaded using 'insmod'
int init_module()
{
  nfho.hook = hook_func;                       //function to call when conditions below met
  //nfho.hooknum = NF_INET_PRE_ROUTING;        //called right after packet recieved, first hook in Netfilter
  nfho.hooknum = NF_INET_LOCAL_IN;
  nfho.pf = PF_INET;                           //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
  nf_register_hook(&nfho);                     //register hook

  nfho_out.hook = hook_func_out;
  nfho_out.hooknum = NF_INET_LOCAL_OUT;
  nfho_out.pf = PF_INET;                           
  nfho_out.priority = NF_IP_PRI_FIRST;             
  nf_register_hook(&nfho_out);

  return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho);                   //cleanup – unregister hook
  nf_unregister_hook(&nfho_out); 
}
