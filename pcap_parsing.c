#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
//#include "if_ether.h"
#include <netinet/if_ether.h>


#define IPV4_ALEN 4 
#define IPV6_ALEN 16
#define HTTP 0x0050
#define HTTP_MAX_LEN 300

struct ipv4_packet{
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
	//option...??
} __attribute__((packed)); //disabled padding

struct ether_frame{
	u_char dest_mac[ETH_ALEN];
	u_char src_mac[ETH_ALEN];
	u_short type; //2byte
}__attribute__((packed));

struct tcp_segment{ 
	u_short src_port; //2byte
	u_short dest_port; //2byte
	u_int seq_number; //4byte
	u_int ack_number; //4byte
	u_char offset_and_reserved;
	u_char flag;
	u_short window; //2byte
	u_short checksum; //2byte
	u_short urgent_pointer; //2byte
	//option...??

}__attribute__((packed));


//only 2byte
void BigEndianToLittleEndian(u_short* data){

	*data = (*data<<8)+(*data>>8);
}



void printMacAddress(u_char* dest, u_char* src, const u_char* packet){
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

void printIpv4Address(u_char* dest, u_char* src, const u_char* packet){
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
	puts("");
}

void printPort(u_short dest, u_short src, const u_char* packet){

	int i = 0;
	printf("[PORT] %hu > %hu\n",src, dest);
}

void printHttp(const u_char* packet){
	int i = 0;
	
	puts("[payload]");
	for(i = 0; i < HTTP_MAX_LEN-1; i++){
		if(packet[i] == 0x0d && packet[i+1] == 0x0a)
			puts("");
		else if(packet[i] < 32 || packet[i] > 127)
			printf(".");
		else
			printf("%c", packet[i]);
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
	u_char *copy_packet = NULL;
	struct ipv4_packet ipv4_header;
	struct ether_frame ether_header;
	struct tcp_segment tcp_header;
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
	/* Grab a packet */
	status = pcap_next_ex(handle, &header, &packet); //read

	if(!status) //no packet
		continue;
	


	printf("=============================================================================\n");
	
	
	memmove(&ether_header, packet, sizeof(struct ether_frame));
	printMacAddress(ether_header.dest_mac, ether_header.src_mac, packet);
	/*set offset*/
	offset = sizeof(struct ether_frame);

	/*Only 2byte Big Endian to Little Endian*/
	BigEndianToLittleEndian(&ether_header.type);

	if(ether_header.type == ETH_P_IP){

		memmove(&ipv4_header, packet+offset, sizeof(struct ipv4_packet));
		printIpv4Address(ipv4_header.dest_ipv4, ipv4_header.src_ipv4, packet+offset);		
		/*plus offset*/
		offset += sizeof(struct ipv4_packet);

		if(ipv4_header.protocol == IPPROTO_TCP){
			memmove(&tcp_header, packet+offset, sizeof(struct tcp_segment));	
			BigEndianToLittleEndian(&tcp_header.dest_port);
			BigEndianToLittleEndian(&tcp_header.src_port);
			
			printPort(tcp_header.dest_port, tcp_header.src_port, packet+offset);
			offset += sizeof(struct tcp_segment);

			if(tcp_header.dest_port == HTTP || tcp_header.src_port == HTTP){
				printHttp(packet+offset);
			}
		}
	}

	printf("=============================================================================\n");
	}	
	
	puts("[-]Closed service");
	
	pcap_close(handle);
	
	return(0);
 }
