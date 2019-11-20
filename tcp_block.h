#pragma once
#include <stdint.h>
#include <pcap.h>
#include <sys/socket.h>
#include <map>


using namespace std;

#define ETHER_ADDR_LEN 6
#define IP_LEN 4

#define IP_HDR_LEN 20
#define TCP_LEN 20
#define eth_hdr_len 14

void block_tcppkt(pcap_t* handle, uint8_t* mymac, uint8_t* myip);

void print_len(uint8_t* s, int n);
void get_myIpaddr(uint32_t* IP_addr, char* interface);
void get_myMacaddr(uint8_t*  mac, char* interface);
void forward_rstpkt(pcap_t* handle, uint8_t* pkt, int ip_len, int tcp_len, int http_len);
void forward_finpkt(pcap_t* handle, uint8_t* pkt, int ip_len, int tcp_len, int http_len);
void backward_rstpkt(pcap_t* handle, uint8_t* pkt, int ip_len, int tcp_len, int http_len);
void backward_finpkt(pcap_t* handle, uint8_t* pkt, int ip_len, int tcp_len, int http_len);
void block_tcppkt(pcap_t* handle, uint8_t* mymac, uint8_t* myip, uint8_t* host_url);
void add_complement(uint32_t* dest, uint16_t src);
uint16_t ip_checksum(uint8_t* ip_packet, int ip_len);
uint16_t tcp_checksum(uint8_t* ip_packet, int ip_len, int tcp_len, int http_len);


struct ethernet_hdr{
	uint8_t dhost[ETHER_ADDR_LEN];
	uint8_t shost[ETHER_ADDR_LEN];
	uint16_t type;
};

struct IP_HDR{
    uint8_t header;  // 4bit version, next 4bit IP header length
    uint8_t tos;     // type of service
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t ttl;      // time to live
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct TCP_HDR{
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
	uint8_t  tcp_len;
    uint8_t  flag;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

