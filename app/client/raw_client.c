//This is a ping which can both send and receive ICMP packets
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define BUFFSIZE 128
#define DEBUG
#ifdef DEBUG
void hexdump(uint8_t *addr, int len)
{
	int i = 0;
	for(i = 0; i < len; i++) {
		if(!(i%16))
			printf("%4x: ", (uint32_t)addr);
		printf("%02x ", *(addr + i));
		if(!((i + 1)%16))
			printf("\n");
	}
	printf("\n");
}
#endif

int main(int argc, char * argv[])
{
	int sockfd;
	char *name = NULL;
	struct ifreq device;
	struct sockaddr_ll addr;
	struct timeval tv;
	char buff[BUFFSIZE] = {0};
	struct ethhdr *eth;
	ssize_t n;
	int i, count;

	memset(buff, 0, BUFFSIZE);

	if(argc != 3) {
		printf("usage: %s <interface> <count> \n", argv[0]);
		exit(1);
	}

	name = argv[1];
	count = atoi(argv[2]);
	printf("Ethernet Port : %s, count = %d\n", name, count);

	sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
#if 1
	memset(&device, 0, sizeof(device));
	strncpy(device.ifr_name, name, sizeof(device.ifr_name));
	if (ioctl(sockfd, SIOCGIFINDEX, &device) < 0) {
		perror("getting interface index fail, check device name");
		return -1;
	}

	addr.sll_ifindex = device.ifr_ifindex;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) < 0)
	{
		perror("bind failed");
		exit(1);
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name)))
	{
		perror("SO_BINDTODEVICE failed");
		exit(1);
	}
#endif
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

	eth = (struct ethhdr *)buff;
	memset(eth->h_dest, 0xff, ETH_ALEN);
	eth->h_source[0] = 0x00;
	eth->h_source[1] = 0x04;
	eth->h_source[2] = 0x9f;
	eth->h_source[3] = 0x05;
	eth->h_source[4] = 0x87;
	eth->h_source[5] = 0xb9;
	eth->h_proto = htons(0x88a4);
#ifdef DEBUG
	hexdump(buff, sizeof(buff));
#endif
	for (i = 0; i < count; i++) {
		//n = sendto(sockfd, buff, BUFFSIZE, 0, NULL, 0);
		n = send(sockfd, buff, BUFFSIZE, 0);
		if(n < 0) {
			perror("failed to send");
			exit(0);
		};
#ifdef DEBUG
		memset(buff, 0, BUFFSIZE);
#endif
		//if((n = recvfrom(sockfd, buff, sizeof(buff), 0, NULL, NULL)) < 0)
		if((n = recv(sockfd, buff, sizeof(buff), 0)) < 0)
		{
			perror("receive error!");
			exit(1);
		};
#ifdef DEBUG
		printf("rx frame dump ...\n");
		hexdump(buff, sizeof(buff));
#endif
	}
	printf("send/recv %d frames done\n", i);
	return 0;
}
