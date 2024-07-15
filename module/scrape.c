#include <stdio.h>
#include <string.h> 
#include <pcap/pcap.h> 
#include <ctype.h>
#include <pthread.h> 
#include <stdlib.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <locale.h>

// struct tcp_head { 
//     unsigned short sport; 
//     unsigned short dport; 
//     unsigned int seq; 
//     unsigned int ack; 
//     unsigned char thl : 4; 
//     unsigned char reserved: 4; 
// };
FILE* log_fp;
struct outputs { 
    // MAC addresses should be max 16 char representation
    char s_mac[18];
    char d_mac[18]; 
    // IPv4 addresses should be max 15 char representation.
    char s_ip[16];
    char d_ip[16]; 
    char s_port[6];
    char d_port[6];

    u_char flags;
    long time; 
    int size; 
};
struct pack_inputs { 
    char *svc;
    char **cap_store;
    int *num;
    struct outputs **output;
    int pipe_fd; 
};
struct mapping { 
    char *svc; 
    char *if_name;
    FILE *fp; 
};


/**
 *  Resolve service <-> interface name mappings.
 *  Resolution process documented in the svc_res.sh script. 
 *  The mappings are stored and returned in a mappings 
 *  struct so they are accessible from outside the function.
 *  @param int* size: Stores the number of mappings 
 *                    found by the script. 
 *  @return mapping**: A structure of [size] mapping 
 *                     structs populated with the 
 *                     required information.
 */
struct mapping** get_svc_mappings(int *size){
    FILE *fp; 
    fprintf(log_fp,"Entered the function");
    char line[1000];
    // Figure out how to arbitrarily add details to mapping 
    fp = popen("./scripts/svc_res.sh | grep '^|' | sed 's/^|//' | sort -u","r");
    if (fp == NULL) { 
        fprintf(log_fp,"Could not resolve mappings."); 
        exit(1); 
    }
    // Read header size of script output.
    if (fgets(line,sizeof(line),fp) != NULL) { 
        *size = atoi(line);
    }
    /*  
        The mapping struct stores the service <-> 
        interface name mappings, with 'size' number
        of mappings. 
    */
    struct mapping **maps = malloc(sizeof(struct mapping*) * *size);
    fprintf(log_fp,"There are %d elements\n",*size);
    int i = 0;

    // Process all the script outputs holding the relevant mappings.
    while (fgets(line,sizeof(line),fp) != NULL) {
        fprintf(log_fp,"Mapping %d: %s",i,line);
        char *token = strtok(line, "|");
        struct mapping* cur = malloc(sizeof(struct mapping)); 
        fprintf(log_fp,"%p address of cur\n",cur);
        int j = 0;
        while (token != NULL) {
            switch (j){
                // TODO check malloc success
                // First field holds the service name.
                case 0: 
                    cur->svc = malloc(strlen(token));
                    strcpy(cur->svc,token);    
                    fprintf(log_fp,"%p -> %s\n",cur->svc,token);
                    break;
                // Second field holds the interface name.
                case 1:
                    cur->if_name = malloc(strlen(token));
                    strcpy(cur->if_name,token); 
                    cur->if_name[strcspn(cur->if_name,"\n")] = 0;
                    fprintf(log_fp,"%p -> %s\n",cur->svc,token);
                    break;
            }
            fprintf(log_fp,"%d : %s\n",j,token);
            token = strtok(NULL, " ");
            j++;
        }
        fprintf(log_fp,"cur %p:\nsvc %p -> %s:\nif %p -> %s\n\n",cur,cur->svc,cur->svc,cur->if_name,cur->if_name);
        maps[i++] = cur;
        // TODO could convert to hashmap 
    }
    // Return the struct holding all the mapping structs.
    return maps;
}

/**
 *  Callback for packet handling operation. Stores all the 
 *  required information for each packet in an output structure, 
 *  which is accessible by the calling process. All the details 
 *  required for the function are passed through a pack_inputs 
 *  struct, which involves dynamic storage for output access. 
 * 
 *  @param u_char* user: A pointer storing all user arguments - used 
 *                          here to store the pack_inputs struct. 
 *  @param pcap_pkthdr* head: The packet header, including sizes and timestamps
 *  @param u_char* content: The packet body, with all the contents.  
 */
void on_packet(u_char *user,const struct pcap_pkthdr* head,const u_char*
        content)
{
    struct pack_inputs* input = (struct pack_inputs*) user; 
    // printf("Struct addresses: %p || %p || %p -> %d\n",&input->svc,input->cap_store,&input->num,*(input->num));
    struct ether_header* eth_h = (struct ether_header*) content; 
    int ether_len = sizeof(struct ether_header); 
    struct ether_addr* smac = (struct ether_addr*) (&eth_h->ether_shost);
    struct ether_addr* dmac = (struct ether_addr*) (&eth_h->ether_dhost);
    fprintf(log_fp,"FROM DEVICE %s\n",input->svc);
    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    struct ip* ip_h = (struct ip*) (content + sizeof(struct ether_header)); 
    int iph_len = (ip_h->ip_hl * 4);  
    u_char protocol = ip_h->ip_p;

    // Dynamically assign storage in the output[x] section so the results are 
    // accessible outside the function 
    ((input->output)[*input->num]) = malloc(sizeof(struct outputs));

    strncpy(((input->output)[*input->num])->s_mac,ether_ntoa(eth_h->ether_shost),17);
    strncpy(((input->output)[*input->num])->d_mac,ether_ntoa(eth_h->ether_dhost),17);
    strncpy(((input->output)[*input->num])->s_ip,inet_ntoa(ip_h->ip_src),15);
    strncpy(((input->output)[*input->num])->d_ip,inet_ntoa(ip_h->ip_dst),15);
    ((input->output)[*input->num])->time = head->ts.tv_sec * (int)1e6 + head->ts.tv_usec;
    ((input->output)[*input->num])->size = head->caplen;

    (input->cap_store[*input->num]) = malloc(head->caplen);
    memcpy(input->cap_store[*input->num],content,head->caplen);

    // *(input->num) = *(input->num) + 1; 

    // for (int i = 0; i<*(input->num);i++){ 
    //     fprintf(log_fp,"%d : %p\n",i,((input->cap_store)[i]));
    //     fprintf(log_fp,"%s || %d\n",(inet_ntoa(ip_h->ip_dst)),strlen(inet_ntoa(ip_h->ip_dst)));
    // }
    if (protocol != IPPROTO_TCP) {
        fprintf(log_fp,"Not a TCP packet: using %u. Skipping...\n",protocol);
        strncpy(((input->output)[*input->num])->s_port,"-1",5);
        *(input->num) = *(input->num) + 1; 
        return;
    }
    struct tcphdr* tcp_h = (struct tcphdr*) (content + sizeof(struct ether_header) + iph_len); 
    int tcph_len = (tcp_h->th_off * 4);
    char sp[6];
    sprintf(sp,"%hu",ntohs(tcp_h->source));
    char dp[6];
    sprintf(dp,"%hu",ntohs(tcp_h->dest));
    (input->output[*input->num])->flags = tcp_h->th_flags;
    fprintf(log_fp,"PORTS %s : %s\n",sp,dp);
    fprintf(log_fp,"Flags: %x\n",tcp_h->th_flags);
    strncpy(((input->output)[*input->num])->s_port,sp,5);
    strncpy(((input->output)[*input->num])->d_port,dp,5);
    // printf("TCPHDRLEN = %d___", tcph_len);
    int total_head_len = ether_len + iph_len + tcph_len;    
    // printf("Total len C,T,H: %d :: %d :: %d",head->caplen,head->len,total_head_len);
    int payload_len = head->caplen - total_head_len;
    // printf("%u : %u___\n",ntohs(tcp_h->th_sport),ntohs(tcp_h->th_dport));
    // for (size_t i = 0; i < (size_t) head->caplen;i++){ 
    //     fprintf(log_fp,"%c",isprint(content[i]) ? content[i] : '.');
    // }
    fprintf(log_fp,"\n");
    *(input->num) = *(input->num) + 1; 
}

/**
 *  Thread handling function responsible for capturing the traffic 
 *  of a single interface over a single service. Opens a libpcap 
 *  listener on each interface, and batches packets. On finishing 
 *  a batch, the output from that batch is piped to the python 
 *  process responsible for interpreting and marking the packets. 
 * 
 *  @param mapping* map: The mapping for the given interface. 
                    Contains all information required to intialise
                    a service capture. 
 */
void capture_interface(struct mapping *map){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle; 
    // char fnames[250];
    // snprintf(fnames,250,"./%s_svc.log",map->svc);
    // FILE* log_files = fopen(fnames,"a");
    // UNCOMMENT BELOW
    FILE *log_files = map->fp;
    if (log_files == NULL) { 
        perror("Failed to open log file."); 
        exit(1); 
    };
    fprintf(log_fp,"Args to interface thread: %s, %s: %d fd\n",map->svc,map->if_name,fileno(log_files));
    // Start a capture on the given interface.
    // TODO: Should return error or remap if no device is availables
    handle = pcap_open_live(map->if_name, BUFSIZ, 0, 262144, errbuf); 
    if (handle == NULL){ 
        fprintf(stderr, "Couldn't open device %s: %s___", map->if_name, errbuf); 
        exit(EXIT_FAILURE);
    }
    // // Get ethernet headers 
    int ll = pcap_datalink(handle);
    fprintf(log_fp,"Link layer %d___",ll);
    if (ll != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported___", map->if_name);
        return;
    }   
    fflush(stdout);
    // pcap_set_timeout(handle,100);
    // Sets the number of packets to capture at a time. Packets are dealt with in batches.
    int BATCH_SIZE = 10; 
    while (1){
        fprintf(log_fp,"Loop %s : %d\n", map->svc,fileno(log_files));
        // This struct should have static references - all 10 packets should 
        // access same addresses for each batch. 
        int num = 0;
        char *captured_contents[BATCH_SIZE];
        struct outputs* results[BATCH_SIZE]; 
        struct pack_inputs input = { .svc=map->svc, .cap_store=captured_contents, .num=&num, .output=results};
        pcap_loop(handle,BATCH_SIZE,on_packet,&input);
        fflush(stdout);
        // Write batch output to the pipe for IPC. 
        for (int i = 0; i < BATCH_SIZE; i++){ 
            if (strcmp("-1",results[i]->s_port)==0){ 
                continue;
            }
            fprintf(log_fp,"%d address at %p\n\t %s -> %s\n\t %s -> %s\n",i,(results[i]),(results[i])->s_mac,results[i]->d_mac,results[i]->s_ip,results[i]->d_ip);        
            // Send all the relevant packet information
            fprintf(log_files,"%s|%s|%s|%s|%s|%s|%s|%ld|%d|%u\n",map->svc,results[i]->s_mac,results[i]->d_mac,
                results[i]->s_ip,results[i]->d_ip,results[i]->s_port,results[i]->d_port,results[i]->time,
                results[i]->size,results[i]->flags);
            fflush(log_files);
            if (ferror(log_files)){ 
                fprintf(log_fp,"Write to pipe failed\n");
            } else { 
                fprintf(log_fp,"Write to pipe succeeded.\n");
            }
        }
    }
    fprintf(log_fp,"Closing");
    pcap_close(handle);
    // fclose(log_files);
}

/**
 *  Initialise and run threads for each service. 
 */
int main(int argc, char *argv[])
{   
    // const char *default_locale = setlocale(LC_CTYPE, NULL);
    // if (default_locale) {
    //     fprintf(log_fp,"Default locale: %s\n", default_locale);
    // } else {
    //     perror("setlocale");  // Handle error if setlocale fails
    // }
    int log_fd = open("./logs/c.log",O_WRONLY | O_CREAT | O_TRUNC); 
    if (log_fd == -1) { 
        perror("Log file opening failed"); 
        exit(EXIT_FAILURE); 
    }
    
    log_fp = fdopen(log_fd, "w");  // Attempt to associate a stream (read mode)

    if (log_fp == NULL) {
        perror("fdopen");
        close(log_fd);  // Close fd even on error
        exit(EXIT_FAILURE);
        return 1;
    }
    int size;
    struct mapping** svcs = get_svc_mappings(&size);
    // printf("SIZE is %d\n",size);
    // Create pipe to write to rule handler.
    char *fifo_name = "traffic_data"; 
    mkfifo(fifo_name,0666);
    log_fd = open("../logs/c.log",O_WRONLY); 
    if (log_fd == -1) { 
        perror("Log file opening failed"); 
        exit(EXIT_FAILURE); 
    }
    // Open write to pipe 
    int fd = open(fifo_name,O_WRONLY);
    // FILE *fp = fopen(fifo_name, "w"  );
    // if (fp == NULL){ 
    if (fd == -1){ 
        perror("Can't open pipe:");
        exit(EXIT_FAILURE);
    }
    FILE *fp = fdopen(fd,"w");
    pthread_t *threads; 
    if ((threads = malloc(size * sizeof(pthread_t))) == NULL) { 
        perror("Failure in thread initialisation:");
        return(1); 
    };
    // Resolve mappings and create thread for each service. 
    for (int i = 0; i < size; i++) { 
        struct mapping *cur = svcs[i]; 
        cur->fp = fp; 
        fprintf(log_fp,"map %d at %p %s -> %s\n",i,cur,cur->svc, cur->if_name);
        fprintf(log_fp,"Creating thread for device %s at %p: i is %d\n",cur->if_name,&threads[i],i);
        int ret = pthread_create( &threads[i], NULL, capture_interface, cur);
    }

    // Initialise threads 
    for (int i = 0; i < size; i++){ 
        pthread_join( threads[i], NULL);
    }
	return(0);
}

