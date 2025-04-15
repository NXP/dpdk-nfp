/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <stdint.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>

static ssize_t s_send_total_bytes;
static ssize_t s_recv_total_bytes;

enum {
	SERVER_MODE,
	CLIENT_MODE
};
static int s_mode = SERVER_MODE;
static unsigned short s_udp_port = 0x1234;
static unsigned int s_len = 64;
static unsigned int s_print_period = 4;

static char s_ip_addr[128];
static int s_quit;

static void
signal_handler(int signum)
{
	s_quit = 1;
}

static const char s_options[] =
	"c" /* Client mode*/
	"s" /* Server mode*/
	"a:" /* Address*/
	"p:" /* UDP port*/
	"l:"; /* Packet length*/

static void parse_args(int argc, char **argv)
{
	int opt;
	int option_index;

next_opt:
	opt = getopt_long(argc, argv, s_options,
		NULL, &option_index);
	if (opt == EOF)
		return;
	switch (opt) {
	case 'c':
		s_mode = CLIENT_MODE;
		break;
	case 's':
		s_mode = SERVER_MODE;
		break;
	case 'a':
		strncpy(s_ip_addr, optarg, strlen(optarg));
		break;
	case 'p':
		s_udp_port = atoi(optarg);
		break;
	case 'l':
		s_len = atoi(optarg);
		break;
	default:
		break;
	}
	goto next_opt;
}

static void *perf_statistics(void *arg)
{
	ssize_t total_tx = 0, total_rx = 0, diff_tx, diff_rx;
	double tx_mbps, rx_mbps;

perf_next:
	sleep(s_print_period);
	diff_tx = s_send_total_bytes - total_tx;
	tx_mbps = ((double)diff_tx) * 8 / 4 / 1000 / 1000;
	total_tx = s_send_total_bytes;

	diff_rx = s_recv_total_bytes - total_rx;
	rx_mbps = ((double)diff_rx) * 8 / 4 / 1000 / 1000;
	total_rx = s_recv_total_bytes;
	printf("%d seconds tx: %ld bytes, %.2fMbps, rx: %ld bytes, %.2fMbps\n",
		s_print_period, total_tx, tx_mbps, total_rx, rx_mbps);
	goto perf_next;

	return arg;
}

struct perf_loop_desc {
	struct sockaddr_in *sock_addr;
	int fd;
	ssize_t len;
	char *buf;
};

static void perf_check_socket_addr(struct sockaddr_in *_addr,
	struct sockaddr_in *sock_addr, char *mode)
{
	if (_addr->sin_family != sock_addr->sin_family) {
		printf("%s read family(%d) != %d\r\n", mode,
			_addr->sin_family, sock_addr->sin_family);
	}

	if (_addr->sin_port != sock_addr->sin_port) {
		printf("%s read port(%04x) != %04x\r\n", mode,
			ntohs(_addr->sin_port), ntohs(sock_addr->sin_port));
	}
	if (_addr->sin_addr.s_addr != sock_addr->sin_addr.s_addr) {
		printf("%s read addr(%08x) != %08x\r\n", mode,
			ntohl(_addr->sin_addr.s_addr),
			ntohl(sock_addr->sin_addr.s_addr));
	}
}

static struct sockaddr s_client_addr;
static int s_client_addr_init;

static void *perf_loop(void *arg)
{
	struct perf_loop_desc *desc = arg;
	struct sockaddr_in *sock_addr = desc->sock_addr;
	ssize_t bytes_write = 0, bytes_read = 0, len = desc->len;
	int fd = desc->fd, ret;
	char *buf = desc->buf;
	socklen_t _addr_len;
	struct sockaddr addr;
	struct sockaddr_in *_addr = (void *)&addr;
	int flags = fcntl(fd, F_GETFL, 0);

	ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (ret)
		printf("set fd=%d nonblock failed(%d)\r\n", fd, ret);

perf_next:
	if (s_mode == CLIENT_MODE) {
		bytes_write = sendto(fd, buf, len, 0,
			(void *)sock_addr, sizeof(struct sockaddr_in));
		if (bytes_write > 0)
			s_send_total_bytes += bytes_write;
		_addr_len = sizeof(struct sockaddr);
		bytes_read = recvfrom(fd, buf, len, 0,
			&addr, &_addr_len);
		if (bytes_read > 0) {
			perf_check_socket_addr(_addr, sock_addr, "Client");
			s_recv_total_bytes += bytes_read;
		}
	} else {
		_addr_len = sizeof(struct sockaddr);
		memset(&addr, 0, sizeof(addr));
		bytes_read = recvfrom(fd, buf, len, 0, &addr, &_addr_len);
		if (bytes_read > 0) {
			if (s_client_addr_init == false)
				memcpy(&s_client_addr, _addr, sizeof(struct sockaddr_in));
			s_client_addr_init = true;
			perf_check_socket_addr(_addr, (void *)&s_client_addr, "Server");
			s_recv_total_bytes += bytes_read;
		}

		if (s_client_addr_init == true) {
			bytes_write = sendto(fd, buf, len, 0, &s_client_addr,
				sizeof(struct sockaddr_in));
			if (bytes_write > 0)
				s_send_total_bytes += bytes_write;
		}
	}
	goto perf_next;

	return arg;
}

int main(int argc, char *argv[])
{
	struct sockaddr_in server_addr;
	int sockfd, i, ret;
	char *buffer;
	ssize_t bytes_read, bytes_write;
	pthread_t pid;
	struct perf_loop_desc desc;

	parse_args(argc, argv);

	if (s_mode == SERVER_MODE) {
		printf("Server mode with ip:%s/udp:%04x\r\n",
			s_ip_addr, s_udp_port);
	} else {
		printf("Client mode to connect ip:%s/udp:%04x\r\n",
			s_ip_addr, s_udp_port);
	}

	buffer = malloc(s_len);
	if (!buffer)
		return -ENOMEM;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = pthread_create(&pid, NULL, perf_statistics, NULL);
	if (ret) {
		printf("create client_statistics failed!(%d)\n", ret);
		return ret;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(s_udp_port);
	server_addr.sin_addr.s_addr = inet_addr(s_ip_addr);
	if (s_mode == SERVER_MODE) {
		ret = bind(sockfd, (struct sockaddr *)&server_addr,
			sizeof(server_addr));
		if (ret) {
			printf("bind fd(%d) failed!(%d)\n", sockfd, ret);
			return ret;
		}
	}

	desc.sock_addr = &server_addr;
	desc.fd = sockfd;
	desc.len = s_len;
	desc.buf = buffer;
	ret = pthread_create(&pid, NULL, perf_loop, &desc);
	if (ret) {
		printf("create perf loop failed!(%d)\n", ret);
		return ret;
	}
	while (!s_quit)
		sleep(1);
	free(buffer);
	close(sockfd);

	return 0;
}
