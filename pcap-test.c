#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>


#define IP_ADDR_LEN 4     // IP 주소 길이를 정의
#define min(x, y) (x) < (y) ? (x) : (y) // 두 값 중 작은 값을 반환하는 매크로

// 이더넷 헤더를 출력하는 함수
void print_Ether_Header(struct ether_header* eth_hdr) {
    printf("\nEthernet Header\n");
    printf("src MAC : ");
    // 이더넷 헤더의 출발 주소를 출력
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x : ", eth_hdr->ether_shost[i]);
    }
    printf("\n");
    printf("dst MAC : ");
    // 이더넷 헤더의 목적지 주소를 출력
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x : ", eth_hdr->ether_dhost[i]);
    }
    printf("\n");
}

// IP 헤더를 출력하는 함수
void print_IP_Header(struct ip* ip_hdr) {
    printf("\nIP Header\n");
    // IP 헤더의 출발 주소를 호스트 바이트 순서로 변환
    uint32_t src = ntohl(ip_hdr->ip_src.s_addr);
    // IP 헤더의 목적지 주소를 호스트 바이트 순서로 변환
    uint32_t dst = ntohl(ip_hdr->ip_dst.s_addr);
    printf("src ip : ");
    // 출발 주소를 출력
    printf("%d.%d.%d.%d\n", src >> 24, (u_char)(src >> 16), (u_char)(src >> 8), (u_char)(src));
    printf("dst ip : ");
    // 목적지 주소를 출력
    printf("%d.%d.%d.%d\n", dst >> 24, (u_char)(dst >> 16), (u_char)(dst >> 8), (u_char)(dst));

    printf("\n");
}

// TCP 헤더를 출력하는 함수
void print_TCP_Header(struct tcphdr* tcp_hdr) {
    printf("\nTCP Header\n");
    // TCP 헤더의 출발 포트를 출력
    printf("src port : %d\n", ntohs(tcp_hdr->th_sport));
    // TCP 헤더의 목적지 포트를 출력
    printf("dst port : %d\n", ntohs(tcp_hdr->th_dport));
}

// 패킷 페이로드를 출력하는 함수
void print_payload(const u_char* packet, uint32_t offset, uint32_t total_len) {
    printf("\nPayload data\n");
    printf("data: ");
    // 데이터의 길이가 오프셋보다 작거나 같다면 데이터가 없다고 출력
    if (total_len <= offset) {
        printf("no DATA\n");
    }
    // 데이터의 길이가 오프셋보다 크다면 출력
    else {
        uint32_t cnt = total_len - offset;
        int len = min(cnt, 10); // 데이터의 길이와 10 중 작은 값을 선택
        // 출력할 데이터 길이만큼 출력
        for (uint8_t i = 0; i < len; i++) {
            printf("%02x | ", *(packet + offset + i));
        }
    }
    printf("\n");
}

// 사용법을 출력하는 함수
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

// 인자를 파싱하는 함수
typedef struct {
    char* dev_;
} Param;

int parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) { // 인자의 개수가 2가 아니면 사용법 출력
        usage();
        return 0;
    }
    param->dev_ = argv[1]; // 인터페이스 이름 설정
    return 1;
}

int main(int argc, char* argv[]) {
    Param param;
    if (!parse(&param, argc, argv)) // 인자 파싱
        return -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    // pcap를 사용하여 인터페이스를 열고 에러를 처리
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet); // 패킷 캡처
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // 히더 정보를 추출
        struct ether_header* eth_hdr = (struct ether_header*)packet;
        struct ip* ip_hdr = (struct ip*)(packet + 14);
        struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + 14 + (ip_hdr->ip_hl) * 4);

        // 이더넷 타입이 IPv4가 아니라면 건너뛰기
        if (ntohs(eth_hdr->ether_type) != 0x0800)
            continue;

        // IP 프로토콜이 TCP가 아니라면 건너뛰기
        if ((ip_hdr->ip_p) != 0x6)
            continue;

        // 헤더와 페이로드 출력
        printf("----------------------------------------------------\n");
        print_Ether_Header(eth_hdr);
        print_IP_Header(ip_hdr);
        print_TCP_Header(tcp_hdr);
        // 패킷에서 데이터가 시작되는 오프셋 계산
        uint32_t offset = 14 + (ip_hdr->ip_hl) * 4 + (tcp_hdr->th_off) * 4;
        print_payload(packet, offset, header->caplen);
        printf("----------------------------------------------------\n");
    }

    pcap_close(pcap); // pcap 종료
}

