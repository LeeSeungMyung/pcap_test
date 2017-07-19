#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#define IPV4_ALEN 4 
#define IPV6_ALEN 16
#define HTTP 0x0050
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
	u_char dest_mac[ETHER_ADDR_LEN];
	u_char src_mac[ETHER_ADDR_LEN];
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


char* my_ether_ntoa_r(const struct ether_addr *addr, char *buf) {
	sprintf (buf, "%02X:%02X:%02X:%02X:%02X:%02X",
	addr->ether_addr_octet[0], addr->ether_addr_octet[1],
	addr->ether_addr_octet[2], addr->ether_addr_octet[3],
	addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
	return buf;
}

void printHttp(u_char* packet, int length){
	int i = 0;
	
	printf("[payload] HTTP Length : %d\n", length);

	for(i = 0; i < length; i++){	
		if(packet[i] == 0x0d && packet[i+1] == 0x0a){ // new line
			puts("");
			i++;

		}
		else if( isprint(packet[i]))
			printf("%c", packet[i]);
		else
			printf(".");
	}
	puts("");

}


struct ether_frame* ether_process(struct ether_frame* ether_header, u_char* length){
	char mac_dest_str[18] = {0,};
	char mac_src_str[18] = {0,};

	my_ether_ntoa_r((struct ether_addr*)ether_header->src_mac, mac_src_str);
	my_ether_ntoa_r((struct ether_addr*)ether_header->dest_mac, mac_dest_str);
	printf("[MAC ] %s > %s\n",mac_src_str, mac_dest_str);
	/*Set offset*/
	*length = sizeof(struct ether_frame);

	/*Big Endian to Little Endian*/
	ether_header->type = ntohs(ether_header->type);

	return ether_header;
}

struct ipv4_packet* ipv4_process(struct ipv4_packet* ipv4_header, u_char* length){	
	char ip_dest_str[16] = {0,};
	char ip_src_str[16] = {0,};
	/*Parsing IPv4 length*/
	*length = (ipv4_header->version_and_length&0x0f)*4; 

	/*IPv4 total_length ntohs*/
	ipv4_header->total_length = ntohs(ipv4_header->total_length);

	/*print IPv4 header(address, length)*/
	inet_ntop(AF_INET, ipv4_header->src_ipv4, ip_src_str,16);
	inet_ntop(AF_INET, ipv4_header->dest_ipv4, ip_dest_str,16);
	printf("[IP  ] %s > %s, IPv4 Length : %hu\n",ip_src_str, ip_dest_str, *length);

	return ipv4_header;
}

struct tcp_segment* tcp_process(struct tcp_segment* tcp_header, u_char* length){

	/*Big Endian to Little Endian*/
	tcp_header->dest_port = ntohs(tcp_header->dest_port);
	tcp_header->src_port = ntohs(tcp_header->src_port);
	
	/*Parsing tcp length*/
	*length = ((tcp_header->length_and_reserved&0xf0)>>4)*4;
	/*Print tcp header(port, length)*/
	printf("[PORT] %hu > %hu, TCP Length : %hu\n",tcp_header->src_port, tcp_header->dest_port, *length);

	return tcp_header;
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
	struct ipv4_packet* ipv4_header;
	struct ether_frame* ether_header;
	struct tcp_segment* tcp_header;
	u_char ether_length = 0;
	u_char ipv4_length = 0;
	u_char tcp_length = 0;
	u_char *copy_packet = NULL;
	int status = 0;

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
	handle = pcap_open_live("dum0", BUFSIZ, 1, 1000, errbuf); //strin wlan0 //hardcoding "dum0"
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


	puts("[*] Starting service");	
	puts("=============================================================================");

	while(1){

		/* Grab a packet*/
		status = pcap_next_ex(handle, &header, &packet);

		/*No packet*/
		if(!status) 
			continue;

		ether_header = ether_process((struct ether_frame*)packet, &ether_length);
		
		/*is IPv4?*/
		if(ether_header->type == ETHERTYPE_IP){
			ipv4_header = ipv4_process((struct ipv4_packet*)((u_char*)ether_header+ether_length), &ipv4_length);
			
			/*is TCP?*/
			if(ipv4_header->protocol == IPPROTO_TCP){
				tcp_header = tcp_process((struct tcp_segment*)((u_char*)ipv4_header+ipv4_length), &tcp_length);
	
				/*is HTTP?*/
				if(tcp_header->dest_port == HTTP || tcp_header->src_port == HTTP){
					if(ipv4_header->total_length > ipv4_length+tcp_length)
						printHttp((u_char*)tcp_header+tcp_length, ipv4_header->total_length-(ipv4_length+tcp_length));
				}
				
			}
		}
		puts("=============================================================================");
	}	
	
	puts("[-] Closed service");
	
	pcap_close(handle);
	
	return(0);
 }
