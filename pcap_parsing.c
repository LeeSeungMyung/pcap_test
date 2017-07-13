#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
//#include "if_ether.h"
#include <netinet/if_ether.h>


#define IPV4_ALEN 4 
#define IPV6_ALEN 16
#define HTTP 0x0050
#define HTTP_MAX_LEN 400
#define OPTION_LEN 40
struct ipv4_packet{
	u_char version_and_length;
	u_char TOS;
	u_short total_length; //2byte
	u_short identification; //2byte
	u_short fragmentOffset; //2byte
	u_char TTL;
	u_char protocol;
	u_short checksum; //2byte
	u_char src_ipv4[IPV4_ALEN];
	u_char dest_ipv4[IPV4_ALEN];
	u_char option[OPTION_LEN]; //option...??
} __attribute__((packed)); //disabled padding

struct ether_frame{
	u_char dest_mac[ETH_ALEN];
	u_char src_mac[ETH_ALEN];
	u_short type; //2byte
} __attribute__((packed));

struct tcp_segment{ 
	u_short src_port; //2byte
	u_short dest_port; //2byte
	u_int seq_number; //4byte
	u_int ack_number; //4byte
	u_char length_and_reserved;
	u_char flag;
	u_short window; //2byte
	u_short checksum; //2byte
	u_short urgent_pointer; //2byte
	u_char option[OPTION_LEN]; //option...??

} __attribute__((packed));



void printMacAddress(u_char* dest, u_char* src){
	int i;
	
	printf("[MAC ] ");

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

void printIpv4Address(u_char* dest, u_char* src, u_char length){
	int i = 0;
	
	printf("[IP  ] ");
	
	for(i = 0; i < IPV4_ALEN; i++){
		printf("%hu",src[i]);
		if(i+1 != IPV4_ALEN) printf(".");
	}
	printf(" > ");
	for(i = 0; i < IPV4_ALEN; i++){
		printf("%hu", dest[i]); 
		if(i+1 != IPV4_ALEN) printf(".");
	}
	printf(", IPv4 Length : %hu\n", length);
}

void printPort(u_short dest, u_short src, u_char length){
	int i = 0;

	printf("[PORT] %hu > %hu, TCP Length : %hu\n",src, dest,length);
}

void printHttp(const u_char* packet){
	int i = 0;
	
	puts("[payload]");

	for(i = 0; i < HTTP_MAX_LEN-1; i++){	
		if(packet[i] == 0x0d && packet[i+1] == 0x0a) // new line
			puts("");
		else if( isprint(packet[i]))
			printf("%c", packet[i]);
		else
			printf(".");
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
	struct ipv4_packet ipv4_header;
	struct ether_frame ether_header;
	struct tcp_segment tcp_header;
	u_char ipv4_length = 0, tcp_length;
	u_char *copy_packet = NULL;
	int i = 0, status = 0, offset = 0;

	/* Set Null*/
	memset(&ipv4_header, 0, sizeof(struct ipv4_packet));
	memset(&ether_header, 0, sizeof(struct ether_frame));
	memset(&tcp_header, 0, sizeof(struct tcp_segment));

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

	/* Grab a packet*/
	status = pcap_next_ex(handle, &header, &packet);

	/*No packet*/
	if(!status)
		continue;
	


	puts("=======================================================================================");
	
	/*Copy Ethernet header*/
	memmove(&ether_header, packet, sizeof(struct ether_frame));

	/*Print ether header*/
	printMacAddress(ether_header.dest_mac, ether_header.src_mac);

	/*Set offset*/
	offset = sizeof(struct ether_frame);

	/*Big Endian to Little Endian*/
	ether_header.type = ntohs(ether_header.type);
	
	/*is IPv4?*/
	if(ether_header.type == ETHERTYPE_IP){

		/*Copy IPv4 header*/
		memmove(&ipv4_header, packet+offset, sizeof(struct ipv4_packet));
		
		/*Parsing IPv4 length*/
		ipv4_length = (ipv4_header.version_and_length&0x0f)*4; 
		
		/*print IPv4 header(address, length)*/
		printIpv4Address(ipv4_header.dest_ipv4, ipv4_header.src_ipv4, ipv4_length);

		/*IPv4 Next*/
		offset += ipv4_length;
		
		/*is TCP?*/
		if(ipv4_header.protocol == IPPROTO_TCP){
			memmove(&tcp_header, packet+offset, sizeof(struct tcp_segment));	
			
			/*Big Endian to Little Endian*/
			tcp_header.dest_port = ntohs(tcp_header.dest_port);
			tcp_header.src_port = ntohs(tcp_header.src_port);
			
			/*Parsing tcp length*/
			tcp_length = ((tcp_header.length_and_reserved&0xf0)>>4)*4;

			/*Print tcp header(port, length)*/
			printPort(tcp_header.dest_port, tcp_header.src_port, tcp_length);
			
			/*TCP Next*/
			offset += tcp_length;

			/*is HTTP?*/
			if(tcp_header.dest_port == HTTP || tcp_header.src_port == HTTP){
				/*Print http packet*/
				printHttp(packet+offset);
			}
			
		}
	}

	puts("=======================================================================================");
	}	
	
	puts("[-]Closed service");
	
	pcap_close(handle);
	
	return(0);
 }
