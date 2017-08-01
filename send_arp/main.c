#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
void getMyMAC(unsigned char* buffer, char* if_name);
int main(int argc, char * argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    unsigned char myMAC[6];
    int iter = 0;
    /*if(argc != 4)
    {
        fprintf(stderr,"Usage: ./main [INTERFACE_NAME] [SENDER_IP] [TARGET_IP]\n");
        return 2;
    }*/

    dev = "enp0s3"; // argv[1]
    printf("Device: %s\n", dev);
    handle = pcap_open_live(dev,BUFSIZ,1,1000000,errbuf);

    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    getMyMAC(myMAC, "enp0s3");

    for(iter = 0; iter < 6; iter++)
    {
        printf("%.2X ",myMAC[iter]);
    }
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
