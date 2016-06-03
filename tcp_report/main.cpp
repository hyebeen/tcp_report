/*
A. Forward RST: 잡힌 패킷과 동일한 방향으로 RST flag를 set하여 전송
B. Forward FIN: 잡힌 패킷과 동일한 방향으로 FIN flag를 set하여 전송
C. Backward RST: 잡힌 패킷과 반대 방향으로 RST flag를 set하여 전송
D. Backward FIN: 잡힌 패킷과 반대 방향으로 RST flag를 set하여 전송
*/

#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

u_char my_mac[] = {0xd0, 0x50, 0x99, 0xa6, 0x09, 0x2a};
u_int8_t my_ip[] = {0x0a, 0x64, 0x6f, 0xaa};

struct tcp {
    u_int8_t eth_dmac[6];   // ether destination mac주소
    u_int8_t eth_smac[6];  // ether source mac주소
    u_int16_t eth_type;   // ether type

    u_int8_t ip_vs__hl;
    u_int8_t ip_tos;
    u_int8_t ip_total_length[2];
    u_int8_t ip_id[2];
    u_int8_t ip_frag_offset[2];
    u_int8_t ip_ttl;
    u_int8_t ip_protocol;
    u_int8_t ip_checksum[2];
    u_int8_t ip_srcaddr[4];
    u_int8_t ip_destaddr[4];

    u_int8_t source_port[2];
    u_int8_t dest_port[2];
    u_int8_t sequence[4];
    u_int8_t acknowledge[4];
    u_int8_t ns:1;
    u_int8_t reserved_part1:3;
    u_int8_t data_offset:4;
    u_int8_t fin:1;
    u_int8_t syn:1;
    u_int8_t rst:1;
    u_int8_t psh:1;
    u_int8_t ack:1;
    u_int8_t urg:1;
    u_int8_t ecn:1;
    u_int8_t cwr:1;
    u_int8_t window;
    u_int8_t checksum;
    u_int8_t urgent_pointer;

};

void Comparison_GET(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main()
{
    pcap_t *handle;
    char *dev = "eth5";
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    pcap_loop(hande, -1, Comparison_GET, NULL);
    pcap_close(handle);
    return(0);
}

void Comparison_GET(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char *get = "GET ";
        libnet_ethernet_hdr *eth_header = (libnet_ethernet_hdr*) packet;
        libnet_ipv4_hdr *ip_header = (libnet_ipv4_hdr*) (packet + sizeof(libnet_ethernet_hdr));
        if((ip_header->ip_p)==IPPROTO_TCP)
        {
            libnet_tcp_hdr *tcp_header = (libnet_tcp_hdr*) (packet + sizeof(libnet_ethernet_hdr) + (ip_header->ip_hl * 4));
            const u_char *get_packet = (packet + sizeof(libnet_ethernet_hdr) + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4));
                           if (memcmp(get , get_packet, 4) == 0)
                           {
                               printf("get\n");
                               printf("Destination IP -> %s\n", inet_ntoa(ip_header->ip_src));
                               printf("Source IP -> %s\n", inet_ntoa(ip_header->ip_dst));

                           }
        }
}
