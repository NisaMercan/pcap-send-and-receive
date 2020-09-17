/*** Pcap  pcap06.c
#  *
#  * 08.09.2020 Nisa Mercan <nisamercan11@gmail.com>
#  * 09.09.2020 -updated- added sendpacket, inject
#  * gcc pcap06.c -lpcap , sudo ./a.out , ping www.google.com
#  * Please do not remove this header.
#  ***/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> /* for uint16_t htons(uint16_t) */
#include <netinet/if_ether.h> 
#include <time.h>
#include <linux/ip.h>


/* Print the packet information */
void print_packet_info(const u_char* packet, struct pcap_pkthdr hdr) {
    printf("@packet_info: Captured packet length: %d\n", hdr.caplen);
    printf("@packet_info: Total packet length: %d\n", hdr.len);
    printf("@packet_info: Packet captured at: %s", ctime((const time_t*)&hdr.ts.tv_sec));
    printf("@packet_info: Ethernet address length is: %d\n", ETHER_HDR_LEN);
}

/* Call back function
 * typedef void (*pcap_handler)(u_char*, const struct pcap_pkthdr*, const u_char*); */
void callback_pkt(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    int i;
    static int count = 1;
    printf("Called %d times.\n", count);
    count++;

    /* filter the type */
    u_char* ptr; /* printing out hardware header info */
    struct ether_header* eth_header;
    struct iphdr* iph_header;
    eth_header = (struct ether_header*)packet;
    iph_header = (struct iphdr*)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("Ethernet type: IP\n");
        printf("IP Addres:%s", inet_ntoa(((struct sockaddr_in*)iph_header)->sin_addr));
        //	    printf("Destination IP ADdress %x", iph->ip_dst); //inet_ntoa(((struct sockaddr_in*)iph_header)->sin_addr));
        printf("\n");
    }
    else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("Ethernet type: ARP\n");
    }
    else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Ethernet type: Reverse ARP\n");
    }

    /* destination address */
    ptr = eth_header->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf(" Destination Address:");
    do {
        printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
    } while (--i > 0);
    printf("\n");

    /* source address */
    ptr = eth_header->ether_shost;
    i = ETHER_ADDR_LEN;
    printf(" Source Address:");
    do {
        printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
    } while (--i > 0);
    printf("\n");
}

int main(int argc, char** argv) {

    int i;
    char* device;                      /* name of the device */
    char errorbuf[PCAP_ERRBUF_SIZE];   /* for error messages. PCAP_ERRBUF_SIZE is defined in pcap.h */
    pcap_t* handle, * h;                    /* to read packets from a network interface */
    const u_char* packet;
    struct pcap_pkthdr hdr;            /* packet_header                */
    struct ether_header* eptr;         /* net/ethernet.h               */
    struct bpf_program fp;             /* to hold the compiled program */
    bpf_u_int32 maskp;                 /* mask of the device           */
    bpf_u_int32 netp;                  /* ip                           */
    pcap_if_t* alldevs, * d;           /* find all devices and print   */


    /* Find a device
     * char *pcap_lookupdev(char *errbuf)
     */
    device = pcap_lookupdev(errorbuf);

    if (device == NULL) /* checking for errors */ {
        printf("@pcap_lookupdev: Error.\n");
        fprintf(stderr, "%s\n", errorbuf);
        exit(1);
    }
    else
        printf("@pcap_lookupdev: Success.\n");



    /* Find all devices
     * int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
     */
    pcap_findalldevs(&alldevs, errorbuf);

    printf("@pcap_findalldevs: Success.\n\t\tNetwork device found: %s\n", alldevs->name);
    // Print the device list
    printf("\t\tOther available devices:\n\n");
    for (d = alldevs; d; d = d->next) {
        printf("\t%d. %s", ++i, d->name);
        if (d->description)
            printf("\t (%s)", d->description);
        else
            printf("\t(Sorry, No description available for this device)");
        for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
            if (a->addr->sa_family == AF_INET)
                printf("\tIP ADDRESS:%s", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
        }
        printf("\n");
    }


    /* Get network address and mask of the device
     * int pcap_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf)
     */
    pcap_lookupnet(device, &netp, &maskp, errorbuf);

    if (pcap_lookupnet(device, &netp, &maskp, errorbuf) == -1) { /* checking for errors */
        printf("@pcap_lookupnet: Could not get information for device: %s\n", errorbuf);
        netp = 0; maskp = 0;
        return 1;
    }
    if (pcap_lookupnet(device, &netp, &maskp, errorbuf) == 0) {
        printf("@pcap_lookupnet: Success.\n");
    }


    /* Open device to get a packet capture descriptor or a handle to a device
     * pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
     */
    handle = pcap_open_live(device, BUFSIZ, 1, 10, errorbuf);

    if (handle == NULL) {
        printf("@pcap_open_live: Could not open the device. pcap_open_live(): %s\n", errorbuf);
        exit(1);
    }
    else
        printf("@pcap_open_live: Success.\n");


    /* Capture packet
     * const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
     */
    packet = pcap_next(handle, &hdr);

    if (packet == NULL) {
        printf("@pcap_next: Could not capture the next packet\n");
    }
    else
        printf("@pcap_next: Success.\n");
    /* Print packet information  */
    print_packet_info(packet, hdr);


    /* Compile the code. (non-optimized)
     * int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
     */
    if (pcap_compile(handle, &fp, argv[1], 0, netp) == -1) {
        fprintf(stderr, "Could not compile. Error calling pcap_compile\n");
        exit(1); //return 2;
    }
    if (pcap_compile(handle, &fp, argv[1], 0, netp) == 0) {
        printf("@pcap_compile: Success.\n"); //return 2;
    }


    /* Set the compiled program as the filter
     * int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
     */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        printf("Error setting filter\n");
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == 0) {
        printf("@pcap_setfilter: Success.\n");
    }


    /* Injecting packets Updated 09.09.2020 08:57
    * int pcap_inject(pcap_t *p, const void *buf, size_t size);
    */
    int bytes_written;
    unsigned char frame[sizeof(struct ether_header) + sizeof(struct ether_arp)];

    bytes_written = pcap_inject(handle, frame, sizeof(frame)); //& kullanmadan
    printf("@pcap_inject: Success. Bytes written %d\n", bytes_written);
    if (pcap_inject(handle, frame, sizeof(frame)) == -1) {
        fprintf(stderr, "Error. \n");
        //exit(1);
    }


    /* Updated 09.09.2020 08:00 */
    pcap_sendpacket(handle, packet, hdr.len); //& kullanmadan	 
    if (pcap_sendpacket(handle, packet, hdr.len) == -1) {
        printf("@pcap_sendpacket: Error.\n");
    }
    if (pcap_sendpacket(handle, packet, hdr.len) == 0) {
        printf("@pcap_sendpacket: Success.\n");
    }



    /* Receive packets continuously
     * int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
     */
    pcap_loop(handle, -1, callback_pkt, NULL);  //pcap_loop(descr,atoi(argv[1]),my_callback,NULL);

    pcap_close(handle);
    return 0;
}


