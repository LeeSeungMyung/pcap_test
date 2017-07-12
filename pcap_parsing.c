#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "if_ether.h"
//#include ""
#define IPV4_ALEN 4 
#define IPV6_ALEN 16

struct ip_packet{
	u_char version;
	u_char TOS;
	u_short tocal_length; //2byte
	u_short identification; //2byte
	u_short fragmentOffset; //2byte
	u_char TTL;
	u_char protocol;
	u_short checksum; //2byte
	u_char dest_ipv4[IPV4_ALEN];
	u_char src_ipv4[IPV4_ALEN];
};
struct ether_frame{
	u_char dest_mac[ETH_ALEN];
	u_char src_mac[ETH_ALEN];
	u_short type; //2byte
};

struct tcp_segment{
	u_char dest_port;
	u_char src_port;

};

u_short BigEndianToLittleEndian(u_short data){

	return (data<<8)+(data>>8);
}
void printMacAddress(u_char* dest, u_char* src, const u_char* packet){
	int i;
	
	printf("[MAC] ");

	for(i = 0; i < ETH_ALEN; i++){
		printf("%02X", src[i]);
		if(i+1 != ETH_ALEN) printf(":");
	}
	printf(" > ");
	for(i = 0; i < ETH_ALEN; i++){
	        printf("%02X", dest[i]);
	        if(i+1 != ETH_ALEN) printf(":");
	}
	puts("");
}

void printIpv4Address(u_char* dest, u_char* src, const u_char* packet){
	int i = 0;
	
	printf("[ IP] ");
	
	for(i = 0; i < IPV4_ALEN; i++){
		printf("%d",src[i]);
		if(i+1 != IPV4_ALEN) printf(".");
	}
	printf(" > ");
	for(i = 0; i < IPV4_ALEN; i++){
		printf("%d", dest[i]);
		if(i+1 != IPV4_ALEN) printf(".");
	}
	puts("");
}


int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct ip_packet ip_header;
	struct ether_frame ether_header;

	int i, status;

	memset(&ip_header, 0, sizeof(struct ip_packet));
	memset(&ether_header, 0, sizeof(struct ether_frame));
	/* Define the device */
	dev = pcap_lookupdev(errbuf);//get interface
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //strin wlan0
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) { //filter
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) { //port 80 set
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	puts("[*]Starting service");
	while(1){
	/* Grab a packet */
	status = pcap_next_ex(handle, &header, &packet); //read
	if(!status) //no packet
		continue;

	memmove(&ether_header, packet, sizeof(struct ether_frame));
	memmove(&ip_header, packet+sizeof(struct ether_frame), sizeof(struct ip_packet));
	
	//2byte big endian to little endian
	ether_header.type = BigEndianToLittleEndian(ether_header.type);

	if(ether_header.type == ETH_P_IP){

		printMacAddress(ether_header.dest_mac, ether_header.src_mac, packet);
		printIpv4Address(ip_header.dest_ipv4, ip_header.src_ipv4, packet);
	}

	printf("header length: %d\n", header->caplen);
	printf("========================\n");
	}	
	
	puts("[-]Closed service");
	
	pcap_close(handle);
	
	return(0);
 }
