#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

char *lookupDevice() {
    char errBuf[PCAP_ERRBUF_SIZE], *devStr;
    devStr = pcap_lookupdev(errBuf);
    if (devStr) {
        printf("get device: %s\n", devStr);
        return devStr;
    } else {
        printf("error: %s\n", errBuf);
        exit(1);
    }
}

void capturePacket(char *device_name) {
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *device = pcap_open_live(device_name, 65535, 1, 0, errBuf);
    if (!device) {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    } else {
        printf("device found: %s\n", device_name);
    }

    struct pcap_pkthdr packet;
    const u_char *pktStr = pcap_next(device, &packet);
    if (!pktStr) {
        printf("did not capture any packet! \n");
        exit(1);
    }

    printf("Packet length: %d\n", packet.len);
    printf("Number of bytes: %d\n", packet.caplen);
    printf("Recieved time: %s\n", ctime((const time_t*)&packet.ts.tv_sec));
    pcap_close(device);
}

void getPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int *id = (int *)arg;
    printf("id: %d\n", ++(*id));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));

    int i;
    for (i=0; i<pkthdr->len; i++) {
        printf(" %02x", packet[i]);
        if ((i + 1) % 16 == 0) {
             printf("\n");
        }
    }
    printf("\n\n");
}

int main() {
    //capturePacket("en1");
    int id = 0;
    char errBuf[PCAP_ERRBUF_SIZE], *device_name;
    device_name = "en1";
    pcap_t *device = pcap_open_live(device_name, 65535, 1, 0, errBuf);
    pcap_loop(device, -1, getPacket, (u_char*)&id);
    pcap_close(device);
    return 0;
}
