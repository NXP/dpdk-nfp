#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <time.h>

#define BUFFSIZE 1024

#undef DEBUG
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

int count = 0;
int count_old = 0;
int count_pps = 0;
timer_t gTimerSTd;
void timer_status_callback(int sig)
{
	count_pps = count - count_old;
	printf("count_pps = %d, counter = %d\n", count_pps, count);
	count_old = count;
}

void stat_timer(void)
{
        struct itimerspec value;
        struct sigevent evp;
        struct timespec now;

        evp.sigev_value.sival_ptr = &gTimerSTd;
        evp.sigev_notify = SIGEV_SIGNAL;
        evp.sigev_signo = SIGUSR1;
        signal(evp.sigev_signo, timer_status_callback);
        clock_gettime(CLOCK_REALTIME, &now);
        now.tv_sec += 2;
        now.tv_nsec = 0;

        value.it_value = now;//waits for 5 seconds before sending timer signal

        value.it_interval.tv_sec = 1;//sends timer signal every 5 seconds
        value.it_interval.tv_nsec = 0;

        printf("start timer \n");
        timer_create(CLOCK_REALTIME, &evp, &gTimerSTd);

        timer_settime(gTimerSTd, TIMER_ABSTIME, &value, NULL);
}

int main(int argc, char *argv[])
{
	char *name = NULL;
	struct ifreq device;
	int sockfd;
	struct sockaddr_ll addr;
	unsigned char buff[BUFFSIZE];
	int n;

	if (argc != 2) {
		fprintf(stderr, "USAGE: server <interface>\n");
		exit(1);
	}
	name = argv[1];

	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	//sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if(sockfd < 0){
		printf("raw socket error!\n");
		exit(1);
	}
#if 1
	memset(&device, 0, sizeof(device));
	strncpy(device.ifr_name, name, sizeof(device.ifr_name));
	printf("Ethernet Port : %s, socket fd = %d, ioctl cmd = 0x%x\n", name, sockfd, SIOCGIFINDEX);
	if (ioctl(sockfd, SIOCGIFINDEX, &device) < 0) {
		perror("getting interface index fail, check device name");
		return -1;
	}
	printf("ioctl return if index = %d\n", device.ifr_ifindex);

	addr.sll_ifindex = device.ifr_ifindex;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) < 0)
	{
		printf("bind failed\n");
		exit(1);
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name)))
	{
		printf("SO_BINDTODEVICE failed\n");
		exit(1);
	}

	stat_timer();

#endif
	while(1) {

		//while((n = recvfrom(sockfd, buff, BUFFSIZE, MSG_DONTWAIT, NULL, NULL)) <= 0);
		while((n = recv(sockfd, buff, BUFFSIZE, MSG_DONTWAIT)) <= 0);
#ifdef DEBUG
		printf("rcv %d frames, len = %d, and echo back\n", count, n);
		hexdump(buff, n);
#endif
		//n == sendto(sockfd, buff, n, 0, NULL, 0);
		n == send(sockfd, buff, n, 0);
		if (n == -1) {
			perror("send error");
			close(sockfd);
			return -1;
		}
		count++;
	}
	close(sockfd);
}
