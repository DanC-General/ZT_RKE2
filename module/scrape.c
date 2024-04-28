#include <stdio.h>
// #include <pcap.h>
#include <string.h> 
#include <pcap/pcap.h> 
// #include <net/ip.h> 
#include <stdlib.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/tcp.h>


void on_packet(u_char *user,const struct pcap_pkthdr* head,const u_char*
        content)
{
	printf("Jacked a packet with length of [%d]:\n", head->len);
    // int i = 0; 
    // while (i < sizeof(content))
    // {
    //     printf("%02X",(int)content[i+14]);
    //     i++;
    // }

    // setuid(0);
    struct ether_header* eth_h = (struct ether_header*) content; 
    struct ether_addr* smac = (struct ether_addr*) (&eth_h->ether_shost);
    struct ether_addr* dmac = (struct ether_addr*) (&eth_h->ether_dhost);
    // dmac.ether_addr_octet = eth_h->ether_dhost;
    // char *shost = malloc(100); 
    // char *dhost = malloc(100);
    // ether_ntohost(shost,smac);
    // ether_ntohost(dhost, dmac);
    // printf("%s : %s || %s : %s\n",ether_ntoa(smac),ether_ntoa(dmac),shost,dhost);
    printf("%s : %s\n",ether_ntoa(smac),ether_ntoa(dmac));
    struct ip* ip_h = (struct ip*) (content + sizeof(struct ether_header)); 
    printf("%s : %s\n",inet_ntoa(ip_h->ip_src),inet_ntoa(ip_h->ip_dst));
    struct tcphdr* tcp_h = (struct tcphdr*) (content + sizeof(struct ether_header) + sizeof(struct ip)); 
    printf("%d : %d\n",tcp_h->th_sport,tcp_h->th_dport);
    char* info = (char *) (content + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    printf("info: %zu %s\n", sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr), info);
    for (size_t i = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr); i < (size_t) head->len;i++){ 
        printf("%c",content[i]);
    }
    printf("\n");
}
int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;		/* The compiled filter expression */
    char filter_exp[] = "port 443";	/* The filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;
    struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
    pcap_if_t *devs = NULL; 
    char dev[100]; 
    if (pcap_findalldevs(&devs,errbuf) == 0){ 
        strncpy(dev,devs->name,100);
        while (devs) { 
            printf("%s - %s\n", devs->name, devs->description); 
            devs = devs->next;
        }
        // pcap_freealldevs(devs); 
    }
    printf("Device is %s\n",dev);
    pcap_t *handle; 
    // Start a capture on the given interface - NULL -> any 
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf); 
    if (handle == NULL){ 
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); 
        return(2);
    }
    // Get ethernet headers 
    // int ll = pcap_datalink(handle);
    // printf("Link layer %d\n",ll);
    // if (ll != DLT_EN10MB) {
    //     fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
    //     return(2);
    // }   
    // printf("Link details: %s\n",pcap_datalink_val_to_description(ll)); 
    // printf("Link name: %s\n",pcap_datalink_val_to_name(ll)); 
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    packet = pcap_next(handle, &header);
	printf("Jacked a packet with length of [%d]\n", header.len);
	// pcap_close(handle);
    // Count 0 -> infinity
    pcap_loop(handle,0,on_packet,NULL);
    pcap_close(handle);
	return(0);
}
