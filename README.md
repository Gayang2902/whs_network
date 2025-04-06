> C, C++ 기반 PCAP API를 활용하여 PACKET의 정보를 출력하는 프로그램 작성
> 

---

### 문제 설명

이더넷 헤더에서 목적지 MAC 주소, 발신지 MAC 주소
IP 헤더에서 목적지 IP 주소, 발신지 IP 주소
TCP 헤더에서 목적지 포트 번호, 발신지 포트 번호

위의 정보들을 TCP 패킷만을 캡처하고 추출해서 출력해주는 프로그램을 작성하면 된다.

패킷의 각 프로토콜 헤더들을 담을 코드는 멘토님이 강의 중에 제공해주신 `myheader.h` 파일의 일부를 사용하였다.

```c

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
    u_char  tcp_flags;
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};
```

## 코드 설명

### 에러 처리

핸들을 얻어오고 캡처 관련 설정을 하는 과정에서 에러 처리 루틴이 필요하기 때문에 아래처럼 별도의 함수를 작성해서 에러가 나면 간략한 설명과 함께 프로그램이 종료되도록 처리하였다.

```c
static handle_error(const char *err_msg)
{
    fprintf(stderr, err_msg);
    exit(EXIT_FAILURE);
}
```

### `main` 함수

```c
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

    puts("TCP PACKET CAPTURE... \
          =====================");
    pcap_loop(handle, 0, callback, NULL);
    pcap_close(handle);

    return 0;
}
```

`main` 함수에는 pcap 사용을 위한 핸들, 에러를 담을 버퍼 그리고 필터 설정에 필요한 구조체 등을 정의하고 설정하는 코드들을 작성하였다.

단순히 설정 과정만을 거치고 `pcap_loop`를 통해 콜백 함수로 흐름을 넘기기 때문에 멘토님의 코드에서 크게 벗어나지 않았다.

### `callback` 함수

```c
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
```

어차피 대부분의 기능은 pcap 라이브러리에 내장되어 있기 때문에 생각보다 할 게 별로 없었다.

콜백 함수의 인자로 받은 `packet` 변수를 멘토님이 제공해주신 헤더 구조체에 캐스팅해서 각각 IP, TCP인지 확인하고 맞다면 포맷에 맞게 이쁘게 출력하도록 작성하였다.

tcpdump의 출력 메시지를 참고해서 시간 정보도 이쁘게 출력했으면 해서 라이브러리에 존재하는 시간 관련 구조체도 가져다가 출력해줬다.

```c
struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
};

struct timeval
{
#ifdef __USE_TIME_BITS64
  __time64_t tv_sec;		/* Seconds.  */
  __suseconds64_t tv_usec;	/* Microseconds.  */
#else
  __time_t tv_sec;		/* Seconds.  */
  __suseconds_t tv_usec;	/* Microseconds.  */
#endif
};
```

페이로드(TCP 페이로드 == 메시지)는 `tcpdump -x` 처럼 헥사값으로 출력되도록 처리하였다.

- 일단은 16 바이트만 출력하도록 해놓았고 더 보고 싶으면 16에서 늘리면 되도록 설정하였다.

```c
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
```

## 컴파일 및 결과 확인

### 컴파일

```bash
$ gcc prac.c -o prac $(pkg-config --libs libpcap)
```

### 실행 및 결과 확인

```bash
$ sudo ./prac enp0s3
```

![image.png](attachment:1f23d417-f7c3-4fb5-89c9-30cde87e9de2:image.png)

![image.png](attachment:3eb5f4ee-44ab-4e36-a6ce-171b3291a140:image.png)

---

### 감사합니다!!!

코드는 github에 올려놓았습니다.

```bash
$ git clone 
```
