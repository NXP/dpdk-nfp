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

#define MAX_LEN_NUM 8

enum {
	SERVER_MODE,
	CLIENT_MODE
};
static int s_mode = SERVER_MODE;
static int s_bidir = true;
static unsigned short s_udp_port = 0x1234;
static unsigned int s_len_num = 1;
static ssize_t s_lens[MAX_LEN_NUM];
static ssize_t s_max_len;

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
	"l:" /* Packet length*/
	"b:" /* Bi-direction*/
	"m:"; /* Packet mix lengths*/

static int
strsplit(char *string, int stringlen,
	char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL)
		goto einval_error;

	for (i = 0; i < stringlen; i++) {
		if (string[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart) {
			tokstart = 0;
			tokens[tok] = &string[i];
			tok++;
		}
		if (string[i] == delim) {
			string[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;

einval_error:
	errno = EINVAL;
	return -1;
}

static int parse_args(int argc, char **argv)
{
	int opt, num, i;
	int option_index;
	char *str_fld[MAX_LEN_NUM];

next_opt:
	opt = getopt_long(argc, argv, s_options,
		NULL, &option_index);
	if (opt == EOF)
		return 0;
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
		s_lens[0] = atoi(optarg);
		break;
	case 'b':
		s_bidir = atoi(optarg);
		break;
	case 'm':
		num = strsplit(optarg, strlen(optarg), str_fld, MAX_LEN_NUM, ',');
		if (num > MAX_LEN_NUM || num < 0)
			return -EINVAL;
		for (i = 0; i < num; i++)
			s_lens[i] = atoi(str_fld[i]);
		s_len_num = num;

		break;
	default:
		break;
	}
	goto next_opt;

	return 0;
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
	if (s_bidir) {
		printf("%d seconds tx: %ld bytes, %.2fMbps, rx: %ld bytes, %.2fMbps\n",
			s_print_period, total_tx, tx_mbps, total_rx, rx_mbps);
	} else if (s_mode == SERVER_MODE) {
		printf("%d seconds rx: %ld bytes, %.2fMbps\n",
			s_print_period, total_rx, rx_mbps);
	} else if (s_mode == CLIENT_MODE) {
		printf("%d seconds tx: %ld bytes, %.2fMbps\n",
			s_print_period, total_tx, tx_mbps);
	}
	goto perf_next;

	return arg;
}

struct perf_loop_desc {
	struct sockaddr_in *sock_addr;
	int fd;
	int len_num;
	ssize_t len[MAX_LEN_NUM];
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

static void print_ip_address(struct sockaddr *sa, const char *str)
{
	char ip_str[1024];
	struct sockaddr_in *sockaddr_ipv4;
	struct sockaddr_in6 *sockaddr_ipv6;
	const char *result;

	switch (sa->sa_family) {
	case AF_INET:
	{
		sockaddr_ipv4 = (void *)sa;
		result = inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr),
			ip_str, sizeof(ip_str));
		if (result)
			printf("IPv4 Address: %s %s.\n", ip_str, str);
		else
			perror("inet_ntop for IPv4");

		break;
	}
	case AF_INET6:
	{
		sockaddr_ipv6 = (struct sockaddr_in6 *)sa;
		result = inet_ntop(AF_INET6, &(sockaddr_ipv6->sin6_addr),
			ip_str, sizeof(ip_str));
		if (result)
			printf("IPv6 Address: %s %s.\n", ip_str, str);
		else
			perror("inet_ntop for IPv6");

		break;
	}
	default:
		printf("Unknown address family: %d\n", sa->sa_family);
		break;
	}
}

static void *perf_loop(void *arg)
{
	struct perf_loop_desc *desc = arg;
	struct sockaddr_in *sock_addr = desc->sock_addr;
	ssize_t bytes_write = 0, bytes_read = 0;
	int fd = desc->fd, ret, len_idx = 0;
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
		bytes_write = sendto(fd, buf, desc->len[len_idx], 0,
			(void *)sock_addr, sizeof(struct sockaddr_in));
		if (bytes_write > 0)
			s_send_total_bytes += bytes_write;
		_addr_len = sizeof(struct sockaddr);
		if (s_bidir) {
			bytes_read = recvfrom(fd, buf, s_max_len, 0,
				&addr, &_addr_len);
			if (bytes_read > 0) {
				perf_check_socket_addr(_addr, sock_addr, "Client");
				s_recv_total_bytes += bytes_read;
			}
		}
	} else {
		_addr_len = sizeof(struct sockaddr);
		bytes_read = recvfrom(fd, buf, s_max_len, 0, (void *)_addr, &_addr_len);
		if (bytes_read > 0)
			s_recv_total_bytes += bytes_read;
		if (s_client_addr_init == false && bytes_read > 0) {
			memcpy(&s_client_addr, _addr, sizeof(struct sockaddr_in));
			s_client_addr_init = true;
			print_ip_address(&s_client_addr, "connected to server");
			perf_check_socket_addr(_addr, (void *)&s_client_addr, "Server");
		}
		if (s_client_addr_init == false || !s_bidir)
			goto perf_next;

		bytes_write = sendto(fd, buf, desc->len[len_idx], 0,
			&s_client_addr, sizeof(struct sockaddr_in));
		if (bytes_write > 0)
			s_send_total_bytes += bytes_write;
	}
	len_idx++;
	if (len_idx == desc->len_num)
		len_idx = 0;
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

	s_lens[0] = 64;
	s_len_num = 1;

	ret = parse_args(argc, argv);
	if (ret) {
		perror("Failed to parse arges\r\n");
		return ret;
	}

	if (s_mode == SERVER_MODE) {
		printf("Server mode with ip:%s/udp:%04x\r\n",
			s_ip_addr, s_udp_port);
	} else {
		printf("Client mode to connect ip:%s/udp:%04x\r\n",
			s_ip_addr, s_udp_port);
	}

	printf("Transmission with packet size(s): ");
	for (i = 0; i < s_len_num; i++) {
		if (s_lens[i] > s_max_len)
			s_max_len = s_lens[i];
		desc.len[i] = s_lens[i];
		printf("%ld", desc.len[i]);
		if (i < (s_len_num - 1))
			printf(", ");
	}
	printf("\r\n");
	desc.len_num = s_len_num;
	buffer = malloc(s_max_len + 10);
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
