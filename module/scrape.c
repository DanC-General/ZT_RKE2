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

struct tcp_head { 
    unsigned short sport; 
    unsigned short dport; 
    unsigned int seq; 
    unsigned int ack; 
    unsigned char thl : 4; 
    unsigned char reserved: 4; 
    // unsigned char 

};

void on_packet(u_char *user,const struct pcap_pkthdr* head,const u_char*
        content)
{
	// printf("Jacked a packet with length of [%d]:___", head->len);
    // int i = 0; 
    // while (i < sizeof(content))
    // {
    //     printf("%02X",(int)content[i+14]);
    //     i++;
    // }

    // setuid(0);
    struct ether_header* eth_h = (struct ether_header*) content; 
    int ether_len = sizeof(struct ether_header); 
    printf("%d ether_len\n",ether_len);
    struct ether_addr* smac = (struct ether_addr*) (&eth_h->ether_shost);
    struct ether_addr* dmac = (struct ether_addr*) (&eth_h->ether_dhost);
    // dmac.ether_addr_octet = eth_h->ether_dhost;
    // char *shost = malloc(100); 
    // char *dhost = malloc(100);
    // ether_ntohost(shost,smac);
    // ether_ntohost(dhost, dmac);
    // printf("%s : %s || %s : %s___",ether_ntoa(smac),ether_ntoa(dmac),shost,dhost);
    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    struct ip* ip_h = (struct ip*) (content + sizeof(struct ether_header)); 
    int iph_len = (ip_h->ip_hl * 4);  
    printf("IPHDRLEN = %d___", iph_len);
    u_char protocol = ip_h->ip_p;
    printf("Protocol %d___",protocol);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n");
        return;
    }
    // printf("%s : %s___",inet_ntoa(ip_h->ip_src),inet_ntoa(ip_h->ip_dst));
    struct tcphdr* tcp_h = (struct tcphdr*) (content + sizeof(struct ether_header) + iph_len); 
    int tcph_len = (tcp_h->th_off * 4);
    printf("TCPHDRLEN = %d___", tcph_len);
    int total_head_len = ether_len + iph_len + tcph_len;
    printf("Total len C,T,H: %d :: %d :: %d",head->caplen,head->len,total_head_len);
    int payload_len = head->caplen - total_head_len;
    if ( payload_len > 0 ){ 
        puts("Message: ");
        char *payload =  content + total_head_len; 
        for (size_t i = 0; i < payload_len; i++){ 
            printf("%c",payload[i]); 
        }
    }
    // printf("%hu : %hu\n",ethernet_header_length + ip_header_length+ content, content + ethernet_header_length + ip_header_length+ sizeof(unsigned short));
    // printf("%hu : %hu___",tcp_h->th_sport,tcp_h->th_dport);
    // char* info = (char *) (content + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    // printf("info: %zu %s___", sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr), info);
    // for (size_t i = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr); i < (size_t) head->len;i++){ 
    //     printf("%c",content[i]);
    // }
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
            printf("%s - %s___", devs->name, devs->description); 
            devs = devs->next;
        }
        // pcap_freealldevs(devs); 
    }
    printf("SIZE is %d ___ ",sizeof(struct tcphdr));
    printf("Device is %s___",dev);
    pcap_t *handle; 
    // Start a capture on the given interface - NULL -> any 
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf); 
    if (handle == NULL){ 
        fprintf(stderr, "Couldn't open device %s: %s___", dev, errbuf); 
        return(2);
    }
    // Get ethernet headers 
    int ll = pcap_datalink(handle);
    printf("Link layer %d___",ll);
    if (ll != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported___", dev);
        return(2);
    }   
    printf("Link details: %s___",pcap_datalink_val_to_description(ll)); 
    printf("Link name: %s___",pcap_datalink_val_to_name(ll)); 
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s___", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s___", filter_exp, pcap_geterr(handle));
        return(2);
    }
    packet = pcap_next(handle, &header);
	printf("Jacked a packet with length of [%d]___", header.len);
	// pcap_close(handle);
    // Count 0 -> infinity
    pcap_loop(handle,0,on_packet,NULL);
    pcap_close(handle);
	return(0);
}


    /* Header lengths in bytes */
    // int ethernet_header_length = 14; /* Doesn't change */
    // int ip_header_length;
    // int tcp_header_length;
    // int payload_length;

    /* Find start of IP header */
    // ip_header = content + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    // ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    // ip_header_length = ip_header_length * 4;
    // printf("IP header length (IHL) in bytes: %d___", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    // u_char protocol = *(ip_header + 9);
    // printf("Protocol %d___",protocol);
    // if (protocol != IPPROTO_TCP) {
    //     printf("Not a TCP packet. Skipping...\n");
    //     return;
    // }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    // tcp_header = content + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    // tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    // tcp_header_length = tcp_header_length * 4;
    // printf("TCP header length in bytes: %d___", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    // int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    // payload_length = head->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    // printf("Payload size: %d bytes___", payload_length);
    // payload = content + total_headers_size;
    // printf("%s : %s___",ether_ntoa(smac),ether_ntoa(dmac));