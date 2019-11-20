#include <pcap.h>
#include <netinet/in.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>

#include "tcp_block.h"


using namespace std;

int main(int argc, char* argv[]){
	uint32_t myip = 0;
	uint8_t mymac[10];
	uint8_t send_ip[10];
	uint8_t target_ip[10];
	char gateway[20];

	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];


	if(argc != 3){
		printf("have 2 argumnets");
		cout << argc << endl;
		return -1;
	}
	
	
	get_myIpaddr(&myip, argv[1]);
	
	get_myMacaddr(mymac, argv[1]);
	
	printf("\nMy IP ADDRESS : ");
	print_len((uint8_t*)&myip, 4);
	printf("\nMy MAC ADDRESS : ");
	print_len(mymac,6);

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);

	if(handle == NULL){
		fprintf(stderr, "couldn't open device %s: %s\n",argv[1],errbuf);
		return -1;
	}

	block_tcppkt(handle, mymac, (uint8_t*)&myip, (uint8_t*)argv[2]);

	pcap_close(handle);
	return 1;
}
