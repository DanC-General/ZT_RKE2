#include <stdio.h>
// #include <pcap.h>
#include <string.h> 
#include <pcap/pcap.h> 

void on_packet(u_char *user,const struct pcap_pkthdr* head,const u_char*
        content)
{
	printf("Jacked a packet with length of [%d]:\n", head->len);
    int i = 0; 
    while (i < sizeof(content))
    {
        printf("%02X",(int)content[i]);
        i++;
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
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
    if (handle == NULL){ 
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); 
        return(2);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }   
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
