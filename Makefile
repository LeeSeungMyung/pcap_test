all: pcap_test 

pcap_test: pcap_parsing.c
	gcc -o pcap_parsing pcap_parsing.c -lpcap


clean:
	rm pcap_parsing
