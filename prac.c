#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <pcap.h>
#include "header.h"

typedef unsigned char u_char;

static handle_error(const char *err_msg)
{
    fprintf(stderr, err_msg);
    exit(EXIT_FAILURE);
}

void print_payload(const u_char *data, int len)
{
    for (int line = 0; line < 16 && line < len; line += 16) {
        printf("\t%#04x: ", line);

        for (int i = 0; i < 16 && i < len; i++) {
            if (line + i < len) {
                printf("%02x ", data[line + i]);
            } else {
                printf("   ");
            }
        }
        puts("");
    }
}

void callback(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
) 
{    
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip;
    struct tcpheader *tcp;
    int ip_header_len;
    int tcp_header_len;

    struct tm *ltime;
    char timebuf[16];

    const u_char *payload;
    int header_len;
    int payload_len;

    // IP 패킷이 아니면 무시
    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }
    ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    ip_header_len = ip->iph_ihl * 4;

    // TCP 패킷이 아니면 무시
    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }    
    tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    tcp_header_len = TH_OFF(tcp) * 4;

    payload = (u_char *)tcp + tcp_header_len;
    header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    payload_len = header->caplen - header_len;

    ltime = localtime(&header->ts.tv_sec);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", ltime);

    // 정보 출력
    printf("[*] PACKET CAPTURED!!!\n");
    printf("[%s.%06ld] IP ", timebuf, header->ts.tv_usec);
    printf("%s:%d > %s:%d\n", 
            inet_ntoa(ip->iph_sourceip), ntohs(tcp->tcp_sport),
            inet_ntoa(ip->iph_destip), ntohs(tcp->tcp_dport));
    printf("Src: (%02x:%02x:%02x:%02x:%02x:%02x), ",
            eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
            eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Dst: (%02x:%02x:%02x:%02x:%02x:%02x)\n",
            eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
            eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("Message: %dbytes\n", payload_len);
    if (payload_len > 0) {
        print_payload(payload, payload_len);
    }
}   

int main(int argc, char **argv)
{
    pcap_t *handle;
    char perr[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;

    if (argc < 2) {
        handle_error("usage: pcap INTERFACE");
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, perr);
    if (handle == NULL) {
        handle_error("ERROR: failed opening device(interface)");
    }

    if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == 1) {
        handle_error("ERROR: failed filter compile");
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        handle_error("ERROR: failed filter setting");
    }

    puts("TCP PACKET CAPTURE...");
    puts("=====================");
    pcap_loop(handle, 0, callback, NULL);
    pcap_close(handle);

    return 0;
}
