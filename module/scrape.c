#include <stdio.h>
// #include <pcap.h>
#include <string.h> 
#include <pcap/pcap.h> 
// #include <net/ip.h> 
#include <ctype.h>
#include <pthread.h> 
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
};

struct outputs { 
    // MAC addresses should be max 16 char representation
    char s_mac[17];
    char d_mac[17]; 
    // IPv4 addresses should be max 15 char representation.
    char s_ip[16];
    char d_ip[16]; 
    // char *s_port;
    // char *d_port;
};
struct pack_inputs { 
    char *dev;
    char **cap_store;
    int *num;
    struct outputs **output;
};

void on_packet(u_char *user,const struct pcap_pkthdr* head,const u_char*
        content)
{
    struct pack_inputs* input = (struct pack_inputs*) user; 
    printf("Struct addresses: %p || %p || %p -> %d\n",&input->dev,input->cap_store,&input->num,*(input->num));
    struct ether_header* eth_h = (struct ether_header*) content; 
    int ether_len = sizeof(struct ether_header); 
    printf("%d ether_len\n",ether_len);
    struct ether_addr* smac = (struct ether_addr*) (&eth_h->ether_shost);
    struct ether_addr* dmac = (struct ether_addr*) (&eth_h->ether_dhost);
    printf("FROM DEVICE %s --> \n %s : %s || ",input->dev,ether_ntoa(eth_h->ether_shost),ether_ntoa(eth_h->ether_dhost));
    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    struct ip* ip_h = (struct ip*) (content + sizeof(struct ether_header)); 
    int iph_len = (ip_h->ip_hl * 4);  
    // printf("IPHDRLEN = %d___", iph_len);
    u_char protocol = ip_h->ip_p;
    ((input->output)[*input->num]) = malloc(sizeof(struct outputs));

    strncpy(((input->output)[*input->num])->s_mac,ether_ntoa(eth_h->ether_shost),16);
    strncpy(((input->output)[*input->num])->d_mac,ether_ntoa(eth_h->ether_dhost),16);
    strncpy(((input->output)[*input->num])->s_ip,inet_ntoa(ip_h->ip_src),15);
    strncpy(((input->output)[*input->num])->d_ip,inet_ntoa(ip_h->ip_dst),15);


    // inet_ntoa(ip_h->ip_src),inet_ntoa(ip_h->ip_dst)

    (input->cap_store[*input->num]) = malloc(head->caplen);
    memcpy(input->cap_store[*input->num],ether_ntoa(eth_h->ether_shost),head->caplen);
    *(input->num) = *(input->num) + 1; 
    for (int i = 0; i<*(input->num);i++){ 
        printf("%d : %p\n",i,((input->cap_store)[i]));
        printf("%s || %d\n",(inet_ntoa(ip_h->ip_dst)),strlen(inet_ntoa(ip_h->ip_dst)));
    }
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n");
        return;
    }
    struct tcphdr* tcp_h = (struct tcphdr*) (content + sizeof(struct ether_header) + iph_len); 
    int tcph_len = (tcp_h->th_off * 4);
    printf("TCPHDRLEN = %d___", tcph_len);
    int total_head_len = ether_len + iph_len + tcph_len;
    printf("Total len C,T,H: %d :: %d :: %d",head->caplen,head->len,total_head_len);
    int payload_len = head->caplen - total_head_len;
    printf("%u : %u___\n",ntohs(tcp_h->th_sport),ntohs(tcp_h->th_dport));
    for (size_t i = 0; i < (size_t) head->caplen;i++){ 
        printf("%c",isprint(content[i]) ? content[i] : '.');
    }
    printf("\n");
    puts("");
}
void capture_interface(char *dev){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle; 
    printf("Device is %s\n",dev);
    // Start a capture on the given interface - NULL -> any 
    handle = pcap_open_live(dev, BUFSIZ, 0, 262144, errbuf); 
    if (handle == NULL){ 
        fprintf(stderr, "Couldn't open device %s: %s___", dev, errbuf); 
        exit(EXIT_FAILURE);
    }
    // // Get ethernet headers 
    int ll = pcap_datalink(handle);
    printf("Link layer %d___",ll);
    if (ll != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported___", dev);
        // return(2);
    }   
    printf("Link details: %s___",pcap_datalink_val_to_description(ll)); 
    printf("Link name: %s___",pcap_datalink_val_to_name(ll)); 
    // if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    //     fprintf(stderr, "Couldn't parse filter %s: %s___", filter_exp, pcap_geterr(handle));
    //     return(2);
    // }
    // if (pcap_setfilter(handle, &fp) == -1) {
    //     fprintf(stderr, "Couldn't install filter %s: %s___", filter_exp, pcap_geterr(handle));
    //     return(2);
    // }
    printf("\nSTARTING LOOP\n");
    fflush(stdout);
    pcap_set_timeout(handle,100);
    // packet = pcap_next(handle, &header);
	// printf("Jacked a packet with length of [%d]___", header.len);
	// pcap_close(handle);
    int BATCH_SIZE = 10; 
    // while (true){}
    // This struct should have static references - all 10 packs should access same addresses
    int *num = malloc(sizeof(int));
    *num = 0;
    char *captured_contents[BATCH_SIZE];
    struct outputs* results[BATCH_SIZE]; 
    printf("Results is %zu bytes of %zu struct size\n",sizeof(results));
    printf("Addresses of %p:\n",&captured_contents);
    for (int i = 0; i<10;i++){ 
        // if ((captured_contents[i] = malloc(sizeof(char) * 4)) == NULL) perror("malloc:");
        printf("%d : %p\n",i,(captured_contents[i]));
    }
    puts("");
    struct pack_inputs input = { .dev=dev, .cap_store=captured_contents, .num=num, .output=results};
    // Count 0 -> infinity
    pcap_loop(handle,BATCH_SIZE,on_packet,&input);
    fflush(stdout);
    pcap_close(handle);
    for (int i = 0; i < BATCH_SIZE; i++){ 
        struct outputs* cur = (results[i]);
        printf("%d address at %p\n\t %s -> %s\n\t %s -> %s\n",i,(results[i]),(results[i])->s_mac,results[i]->d_mac,results[i]->s_ip,results[i]->d_ip);        
    }
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
    pthread_t *threads; 
    char *interfaces[] = {
        // "lo",
        "eth0",
    };
    int NUM_THREADS = sizeof(interfaces) / sizeof(char *); 
    printf("There are %d threads.\n",NUM_THREADS);
    // Create thread for each k8s network
    if ((threads = malloc(NUM_THREADS * sizeof(pthread_t))) == NULL) { 
        perror("Failure in thread initialisation:");
        return(1); 
    };
    // Initialise threads 
    int ret;
    for (int i = 0; i < NUM_THREADS; i++){ 
        printf("Creating thread for device %s at %p: i is %d\n",interfaces[i],&threads[i],i);
        ret = pthread_create( &threads[i], NULL, capture_interface, interfaces[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++){ 
        pthread_join( threads[i], NULL);
    }

	return(0);
}

