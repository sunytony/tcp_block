#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>

#include <iostream>

#include "tcp_block.h"

using namespace std;

const char* HTTP_METHOD[] = {"GET","POST","HEAD","PUT","DELETE","OPTIONS"};

void print_len(uint8_t* s, int num){
	for(int i = 0; i< num; ++i)
		printf("%x ",s[i]);
}

void get_myIpaddr(uint32_t* IP_addr, char* interface){
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	struct sockaddr_in* sin;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(sock, SIOCGIFADDR, &ifr);

	sin = (struct sockaddr_in*)&ifr.ifr_addr;

	*IP_addr =(uint32_t) sin->sin_addr.s_addr;
	close(sock);
	printf("get_myIPaddr func finish!\n");
}

void get_myMacaddr(uint8_t*  mac, char* interface){
	int sock;
	struct ifreq ifr;
	char mac_adr[18] = {0,}; 

	sock = socket(AF_INET, SOCK_STREAM, 0);

	strcpy(ifr.ifr_name, interface);
	ioctl(sock, SIOCGIFHWADDR, &ifr);
	
	memcpy(mac, ifr.ifr_hwaddr.sa_data,6);
	close(sock);
	printf("get_mymacaddr func finish\n");
}

void block_tcppkt(pcap_t* handle, uint8_t* mymac, uint8_t* myip, uint8_t* host_url){
	struct pcap_pkthdr* header;
	uint8_t* rcvpkt;
	struct IP_HDR* pkt_iphdr;
	struct TCP_HDR* pkt_tcphdr;

	while(1){
		pcap_next_ex(handle, &header, (const u_char **)&rcvpkt);
		if(memcmp(rcvpkt + 6, mymac, 6) != 0) {
			continue;
		}

		pkt_iphdr = (IP_HDR*)(rcvpkt + eth_hdr_len);
		int IP_len = ((pkt_iphdr->header) & 15) * 4;
		int total_len = ntohs(*((uint16_t*)(rcvpkt + eth_hdr_len + 2)));
		if(pkt_iphdr->protocol != 6){
			continue;
		}

		pkt_tcphdr = (TCP_HDR*)(rcvpkt + eth_hdr_len + IP_len);
		int TCP_len = ((pkt_tcphdr->tcp_len) & 0xF0) / 4;
		
		int HTTP_len = total_len - IP_len - TCP_len;

		if(HTTP_len == 0){
			continue;
		}

		uint8_t* http_pkt = rcvpkt + eth_hdr_len + IP_len + TCP_len;

		int i = 0;
		for(i = 0; i < 6; ++i){
			if(memcmp(HTTP_METHOD[i], http_pkt, strlen(HTTP_METHOD[i])) != 0)
				break;
		}

		if(i == 6){
			continue;
		}
		
		int indexOfHost = 0;
		while(http_pkt[indexOfHost] != 0xd || http_pkt[indexOfHost + 1] != 0xa || memcmp(http_pkt + indexOfHost + 2, "Host", 4) != 0){
			indexOfHost++;
			if(indexOfHost == HTTP_len - 5){
				printf("No host\n");
				break;
			}
		}

		if(indexOfHost == HTTP_len - 5){
			continue;
		}

		if(memcmp(host_url, http_pkt + indexOfHost + 8, strlen((const char*)host_url)) == 0){
			printf("Block the this output\n");
			backward_rstpkt(handle, rcvpkt, IP_len,	TCP_len, HTTP_len);
			forward_rstpkt(handle, rcvpkt, IP_len, TCP_len, HTTP_len);
		}
	}
}

void forward_rstpkt(pcap_t* handle, uint8_t* pkt, int ip_len, int tcp_len, int http_len){
	uint8_t packet[eth_hdr_len + ip_len + tcp_len];
	struct IP_HDR* packet_ip = (struct IP_HDR*)(packet + eth_hdr_len);
	struct IP_HDR* rcvpacket_ip = (struct IP_HDR*)(pkt + eth_hdr_len);
	struct TCP_HDR* packet_tcp = (struct TCP_HDR*)(packet + eth_hdr_len + ip_len);
	struct TCP_HDR* rcvpacket_tcp = (struct TCP_HDR*)(pkt + eth_hdr_len + ip_len);
	
	// copy received packet to rstpkt ethernet and ip and tcp
	memcpy(packet, pkt, eth_hdr_len + ip_len + tcp_len);
	packet_ip->total_length = htons(ip_len + tcp_len);

	// set tos
	//packet_ip->tos = 0x44;

	// set rst flag
	packet_tcp->flag = 0x14;

	// set seq
	packet_tcp->seq_num = htonl(ntohl(rcvpacket_tcp->seq_num) + http_len);

	// set window size
	packet_tcp->window_size = 0;

	// calculate checksum
	packet_tcp->checksum = 0;
	packet_tcp->checksum = htons(tcp_checksum(packet + eth_hdr_len, ip_len, tcp_len, 0));
	packet_ip->checksum = 0;
	packet_ip->checksum = htons(ip_checksum(packet + eth_hdr_len, ip_len));
	
	pcap_sendpacket(handle, packet, eth_hdr_len + ip_len + tcp_len);
}

void forward_finpkt(pcap_t* handle, uint8_t* pkt, int ip_len, int tcp_len, int http_len){
	uint8_t packet[eth_hdr_len + ip_len + tcp_len];
	struct pcap_pkthdr* header;
	uint8_t* rcvpkt;
	uint32_t seq_num;
	uint32_t ack_num;
	uint32_t dest_ip;

	struct IP_HDR* packet_ip = (struct IP_HDR*)(packet + eth_hdr_len);
	struct IP_HDR* rcvpacket_ip = (struct IP_HDR*)(pkt + eth_hdr_len);
	struct TCP_HDR* packet_tcp = (struct TCP_HDR*)(packet + eth_hdr_len + ip_len);
	struct TCP_HDR* rcvpacket_tcp = (struct TCP_HDR*)(pkt + eth_hdr_len + ip_len);
	
	// copy received packet to rstpkt ethernet and ip and tcp
	memcpy(packet, pkt, eth_hdr_len + ip_len + tcp_len);
	packet_ip->total_length = htons(ip_len + tcp_len);

	// set rst flag
	packet_tcp->flag = 0x11;

	// set seq
	packet_tcp->seq_num = htonl(ntohl(rcvpacket_tcp->seq_num) + http_len);

	// calculate checksum
	packet_tcp->checksum = 0;
	packet_tcp->checksum = htons(tcp_checksum(packet + eth_hdr_len, ip_len, tcp_len, 0));
	packet_ip->checksum = 0;
	packet_ip->checksum = htons(ip_checksum(packet + eth_hdr_len, ip_len));
	
	pcap_sendpacket(handle, packet, eth_hdr_len + ip_len + tcp_len);

	
	dest_ip = rcvpacket_ip->dest_ip;

	while(1){
		struct IP_HDR* pkt_iphdr;
		struct TCP_HDR* pkt_tcphdr;
		pcap_next_ex(handle, &header, (const u_char **)&rcvpkt);

		if(ntohs(*(uint16_t*)(rcvpkt + 12)) != 0x800){
			cout << "this is not ip packet" << endl;
			continue;
		}

		pkt_iphdr = (IP_HDR*)(rcvpkt + eth_hdr_len);
		int IP_len = ((pkt_iphdr->header) & 15) * 4;
		
		if(pkt_iphdr->src_ip != dest_ip){
			printf("%x\n",pkt_iphdr->src_ip);
			cout << "this is not from ban url" << endl;
			continue;
		}

		if(pkt_iphdr->protocol != 6){
			continue;
		}

		pkt_tcphdr = (TCP_HDR*)(rcvpkt + eth_hdr_len + IP_len);
	
		if(pkt_tcphdr->flag == 0x11){
			seq_num = ntohl(pkt_tcphdr->seq_num);
			ack_num = ntohl(pkt_tcphdr->ack_num);
			cout << "I found fin packet" << endl;
			break;
		}
		cout << "this is not fin/ack packet" << endl;
	}

	packet_tcp->ack_num = htonl(seq_num + 1);
	packet_tcp->seq_num = htonl(ack_num);

	packet_tcp->flag = 0x10;

	// calculate checksum
	packet_tcp->checksum = 0;
	packet_tcp->checksum = htons(tcp_checksum(packet + eth_hdr_len, ip_len, tcp_len, 0));
	packet_ip->checksum = 0;
	packet_ip->checksum = htons(ip_checksum(packet + eth_hdr_len, ip_len));

	pcap_sendpacket(handle, packet, eth_hdr_len + ip_len + tcp_len);
}

void backward_rstpkt(pcap_t* handle, uint8_t* pkt, int ip_len, int tcp_len, int http_len){
	cout << tcp_len << endl;
	uint8_t packet[eth_hdr_len + ip_len + tcp_len];
	struct IP_HDR* packet_ip = (struct IP_HDR*)(packet + eth_hdr_len);
	struct IP_HDR* rcvpacket_ip = (struct IP_HDR*)(pkt + eth_hdr_len);
	struct TCP_HDR* packet_tcp = (struct TCP_HDR*)(packet + eth_hdr_len + ip_len);
	struct TCP_HDR* rcvpacket_tcp = (struct TCP_HDR*)(pkt + eth_hdr_len + ip_len);


	// copy received packet to rstpkt ethernet and ip and tcp
	memcpy(packet, pkt, eth_hdr_len + ip_len + tcp_len);
	packet_ip->total_length = htons(ip_len + tcp_len);

	// swap the mac address and ip address and port 
	memcpy(packet + 6, pkt, 6);
	memcpy(packet, pkt + 6, 6);
	memcpy(packet + eth_hdr_len + 12, pkt + eth_hdr_len + 16, 4);
	memcpy(packet + eth_hdr_len + 16, pkt + eth_hdr_len + 12, 4); 
	memcpy(packet + eth_hdr_len + ip_len, pkt + eth_hdr_len + ip_len + 2, 2);
	memcpy(packet + eth_hdr_len + ip_len + 2, pkt + eth_hdr_len + ip_len, 2);

	// set tos
	//packet_ip->tos = 0x44;

	// set rst flag
	packet_tcp->flag = 0x14;

	// set ack, seq
	packet_tcp->seq_num = rcvpacket_tcp->ack_num;
	packet_tcp->ack_num = htonl(ntohl(rcvpacket_tcp->seq_num) + http_len);

	// set window size
	packet_tcp->window_size = 0;

	// calculate checksum
	packet_tcp->checksum = 0;
	packet_tcp->checksum = htons(tcp_checksum(packet + eth_hdr_len, ip_len, tcp_len, 0));
	packet_ip->checksum = 0;
	packet_ip->checksum = htons(ip_checksum(packet + eth_hdr_len, ip_len));

	pcap_sendpacket(handle, packet, eth_hdr_len + ip_len + tcp_len);
}

void backward_finpkt(pcap_t* handle, uint8_t* pkt, int ip_len, int tcp_len, int http_len){
	uint8_t packet[eth_hdr_len + ip_len + tcp_len + 6];
	struct pcap_pkthdr* header;
	uint8_t* rcvpkt;
	uint32_t seq_num;
	uint32_t ack_num;
	uint32_t dest_ip;

	struct IP_HDR* packet_ip = (struct IP_HDR*)(packet + eth_hdr_len);
	struct IP_HDR* rcvpacket_ip = (struct IP_HDR*)(pkt + eth_hdr_len);
	struct TCP_HDR* packet_tcp = (struct TCP_HDR*)(packet + eth_hdr_len + ip_len);
	struct TCP_HDR* rcvpacket_tcp = (struct TCP_HDR*)(pkt + eth_hdr_len + ip_len);


	// copy received packet to rstpkt ethernet and ip and tcp
	memcpy(packet, pkt, eth_hdr_len + ip_len + tcp_len);
	packet_ip->total_length = htons(ip_len + tcp_len + 2);

	// swap the mac address and ip address and port 
	memcpy(packet + 6, pkt, 6);
	memcpy(packet, pkt + 6, 6);
	memcpy(packet + eth_hdr_len + 12, pkt + eth_hdr_len + 16, 4);
	memcpy(packet + eth_hdr_len + 16, pkt + eth_hdr_len + 12, 4); 
	memcpy(packet + eth_hdr_len + ip_len, pkt + eth_hdr_len + ip_len + 2, 2);
	memcpy(packet + eth_hdr_len + ip_len + 2, pkt + eth_hdr_len + ip_len, 2);

	// set rst flag
	packet_tcp->flag = 0x11;

	// set ack, seq
	packet_tcp->seq_num = rcvpacket_tcp->ack_num;
	packet_tcp->ack_num = htonl(ntohl(rcvpacket_tcp->seq_num) + http_len);

	// set tcp data
	packet[eth_hdr_len + ip_len + tcp_len] = 'a';
	packet[eth_hdr_len + ip_len + tcp_len + 1] = 'b';

	// calculate checksum
	packet_tcp->checksum = 0;
	packet_tcp->checksum = htons(tcp_checksum(packet + eth_hdr_len, ip_len, tcp_len, 2));
	packet_ip->checksum = 0;
	packet_ip->checksum = htons(ip_checksum(packet + eth_hdr_len, ip_len));

	pcap_sendpacket(handle, packet, eth_hdr_len + ip_len + tcp_len + 2);

	dest_ip = rcvpacket_ip->dest_ip;
	printf("%x\n", dest_ip);
	
	while(1){
		struct IP_HDR* pkt_iphdr;
		struct TCP_HDR* pkt_tcphdr;
		pcap_next_ex(handle, &header, (const u_char **)&rcvpkt);
		printf("%x\n",pkt_iphdr->dest_ip);
		if(ntohs(*(uint16_t*)(rcvpkt + 12)) != 0x800){
			cout << "this is not ip packet" << endl;
			continue;
		}

		pkt_iphdr = (IP_HDR*)(rcvpkt + eth_hdr_len);
		int IP_len = ((pkt_iphdr->header) & 15) * 4;
		cout << IP_len << endl;
		if(pkt_iphdr->dest_ip != dest_ip){
			cout << "this is not from ban url" << endl;
			continue;
		}

		if(pkt_iphdr->protocol != 6){
			continue;
		}

		pkt_tcphdr = (TCP_HDR*)(rcvpkt + eth_hdr_len + IP_len);
	
		if(pkt_tcphdr->flag == 0x11){
			seq_num = ntohl(pkt_tcphdr->seq_num);
			ack_num = ntohl(pkt_tcphdr->ack_num);
			cout << "I Found fin packet" << endl;
			break;
		}
		printf("%x\n",pkt_tcphdr->flag); 
		cout << "this is not fin/ack packet" << endl;
	}

	packet_tcp->ack_num = htonl(seq_num + 1);
	packet_tcp->seq_num = htonl(ack_num);

	packet_tcp->flag = 0x10;
	packet_ip->total_length = htons(ip_len + tcp_len);

	// calculate checksum
	packet_tcp->checksum = 0;
	packet_tcp->checksum = htons(tcp_checksum(packet + eth_hdr_len, ip_len, tcp_len, 0));
	packet_ip->checksum = 0;
	packet_ip->checksum = htons(ip_checksum(packet + eth_hdr_len, ip_len));


	pcap_sendpacket(handle, packet, eth_hdr_len + ip_len + tcp_len);
}

uint16_t tcp_checksum(uint8_t* ip_packet, int ip_len, int tcp_len, int http_len){
	struct IP_HDR* ip_header = (struct IP_HDR*)ip_packet; 
	uint32_t result_checksum = 0;
	// calculate pseudo_header
	add_complement(&result_checksum, ntohs((uint16_t)((ip_header->src_ip & 0xffff0000) / 65536)));
	add_complement(&result_checksum, ntohs((uint16_t)(ip_header->src_ip & 0x0000ffff)));
	add_complement(&result_checksum, ntohs((uint16_t)((ip_header->dest_ip & 0xffff0000) / 65536)));
	add_complement(&result_checksum, ntohs((uint16_t)(ip_header->dest_ip & 0x0000ffff)));
	add_complement(&result_checksum, 6);
	add_complement(&result_checksum, (uint16_t)(tcp_len + http_len));
	
	// calculate tcp section
	for(int i = 0; i < tcp_len + http_len; i += 2){
		add_complement(&result_checksum, ntohs(*(uint16_t*)(ip_packet + ip_len + i)));
	}
	
	result_checksum = ~(uint16_t)result_checksum;

	return (uint16_t)result_checksum;
}

uint16_t ip_checksum(uint8_t* ip_packet, int ip_len){
	uint32_t result_checksum = 0;
	for(int i = 0; i < ip_len; i += 2){
		add_complement(&result_checksum, ntohs(*(uint16_t*)(ip_packet + i)));
	}

	result_checksum = ~(uint16_t)result_checksum;

	return (uint16_t)result_checksum;
}

void add_complement(uint32_t* dest, uint16_t src){
	(*dest) += (uint32_t)src;
	if(*dest >= 0x10000){
		*dest -= 0xffff;
	}
}