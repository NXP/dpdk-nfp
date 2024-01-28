#include "netwrap_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include "netwrap_errno.h"
#include "netwrap_socket.h"
#include "netwrap_log.h"

static int setup_socket_wrappers_called;
static int setup_dpdk_called = 0;
int usect_sockfd = 0;
static int (*libc_socket)(int, int, int);
static int (*libc_shutdown)(int, int);
static int (*libc_close)(int);
static int (*libc_bind)(int, const struct sockaddr*, socklen_t);
static int (*libc_accept)(int, struct sockaddr*, socklen_t*);
static int (*libc_accept4)(int, struct sockaddr*, socklen_t*, int);
static int (*libc_listen)(int, int);
static int (*libc_connect)(int, const struct sockaddr*, socklen_t);
static ssize_t (*libc_read)(int, void*, size_t);
static ssize_t (*libc_write)(int, const void*, size_t);
static ssize_t (*libc_recv)(int, void*, size_t, int);
static ssize_t (*libc_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static ssize_t (*libc_send)(int, const void*, size_t, int);
static ssize_t (*libc_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*libc_recvmsg)(int, struct msghdr *, int);
static ssize_t (*libc_sendmsg)(int, const struct msghdr *, int);

int dpdk_recv(int sockfd, void *buf, size_t len, int flags);
int dpdk_send(int sockfd, const void *buf, size_t len, int flags);

void setup_socket_wrappers(void)
{
	LIBC_FUNCTION(socket);
	LIBC_FUNCTION(shutdown);
	LIBC_FUNCTION(close);
	LIBC_FUNCTION(bind);
	LIBC_FUNCTION(accept);
	LIBC_FUNCTION(accept4);
	LIBC_FUNCTION(listen);
	LIBC_FUNCTION(connect);
	LIBC_FUNCTION(read);
	LIBC_FUNCTION(write);
	LIBC_FUNCTION(recv);
	LIBC_FUNCTION(recvfrom);
	LIBC_FUNCTION(send);
	LIBC_FUNCTION(sendto);
	setup_socket_wrappers_called = 1;
}

int netwrap_main_ctor(void);
#ifdef DPDK_TEST
int dpdk_test(void);
#endif
int socket(int domain, int type, int protocol)
{
	int sockfd = -1;

	if (setup_socket_wrappers_called) {
		if (!((domain == AF_INET) && (type == SOCK_DGRAM))) {
			sockfd = (*libc_socket)(domain, type, protocol);
			ECAT_DBG("libc_socket domain = 0x%x, type = 0x%x, proto = 0x%04x, sockfd = %d\n",
					domain, type, ntohs(protocol), sockfd);
		} else {
			int ret;
			if (!setup_dpdk_called) {
#ifdef DPDK_TEST
				ret = dpdk_test();
#else
				ret = netwrap_main_ctor();
#endif
				if (ret) {
					setup_dpdk_called = 1;
				}
			}
			if (usect_sockfd == 0) {
				sockfd = (*libc_socket)(domain, type, protocol);
				usect_sockfd = sockfd;
			} else {
				printf("Only 1 DPDK Socket is supported\n");
				exit(0);
			}
			printf("DPDK Socket domain = 0x%x, type = 0x%x, proto = 0x%04x, sockfd = %d\n",
					domain, type, ntohs(protocol), usect_sockfd);
		}
	} else { /* pre init*/
		LIBC_FUNCTION(socket);

		if (libc_socket) {
			sockfd = (*libc_socket)(domain, type, protocol);
			ECAT_DBG("libc_socket domain = 0x%x, type = 0x%x, proto = 0x%04x, sockfd = %d\n",
					domain, type, ntohs(protocol), sockfd);
		} else {
			sockfd = -1;
			errno = EACCES;
		}
	}

	//ECAT_DBG("socket wrapper return: %d\n", sockfd);
	return sockfd;
}

int shutdown(int sockfd, int how)
{
	int shutdown_value;

	if (IS_USECT_SOCKET(sockfd)) {
		shutdown_value = (*libc_shutdown)(sockfd, how);
		usect_sockfd = 0;
		printf("DPDP socket fd:%d shutdown\n", sockfd);
	} else if (libc_shutdown) {
		ECAT_DBG("libc_shutdown socket fd:%d shutdown\n", sockfd);
		shutdown_value = (*libc_shutdown)(sockfd, how);
	} else {
		LIBC_FUNCTION(shutdown);
		ECAT_DBG("libc_shutdown socket fd:%d shutdown\n", sockfd);

		if (libc_shutdown)
			shutdown_value = (*libc_shutdown)(sockfd, how);
		else {
			shutdown_value = -1;
			errno = EACCES;
		}
	}

	return shutdown_value;
}

int close(int sockfd)
{
	int close_value;

	if (IS_USECT_SOCKET(sockfd)) {
		printf("DPDP socket fd:%d close\n", sockfd);
		close_value = (*libc_close)(sockfd);
		usect_sockfd = 0;
	} else if (libc_close) {
		ECAT_DBG("libc_close socket fd:%d close\n", sockfd);
		close_value = (*libc_close)(sockfd);
	} else { /* pre init*/
		LIBC_FUNCTION(close);
		ECAT_DBG("libc_close socket fd:%d close\n", sockfd);

		if (libc_close)
			close_value = (*libc_close)(sockfd);
		else {
			close_value = -1;
			errno = EACCES;
		}
	}
#if 0
	ECAT_DBG("Socket '%d' closed returns:'%d'\n",
		sockfd, close_value);
#endif
	return close_value;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int bind_value = -1;

	if (IS_USECT_SOCKET(sockfd)) {
		printf("DPDP socket fd:%d bind\n", sockfd);
		return 0;
	} else if (libc_bind) {
		ECAT_DBG("libc_bind socket fd:%d bind\n", sockfd);
		bind_value = (*libc_bind)(sockfd, addr, addrlen);
	} else { /* pre init*/
		LIBC_FUNCTION(bind);

		ECAT_DBG("libc_bind socket fd:%d bind\n", sockfd);
		if (libc_bind)
			bind_value = (*libc_bind)(sockfd, addr, addrlen);
		else {
			bind_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Binding socket '%d' to the address '%x:%d' returns:%d\n",
		sockfd,	((const struct sockaddr_in *)addr)->sin_addr.s_addr,
		odp_be_to_cpu_16(((const struct sockaddr_in *)addr)->sin_port),
		bind_value);*/
	return bind_value;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int accept_value = -1;

	if (IS_USECT_SOCKET(sockfd)) {
		printf("DPDP socket fd:%d accept\n", sockfd);
	} else if (libc_accept) {
		ECAT_DBG("libc_accept socket fd:%d accept\n", sockfd);
		accept_value = (*libc_accept)(sockfd, addr, addrlen);
	} else { /* pre init*/
		LIBC_FUNCTION(accept);
		ECAT_DBG("libc_accept socket fd:%d accept\n", sockfd);

		if (libc_accept)
			accept_value = (*libc_accept)(sockfd, addr, addrlen);
		else {
			accept_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Accept called on socket '%d' returned:'%d'\n",
		sockfd, accept_value);*/
	return accept_value;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int accept_value = -1;

	if (IS_USECT_SOCKET(sockfd)) {
		ECAT_DBG("DPDP socket fd:%d accept4\n", sockfd);
	} else if (libc_accept4) {
		ECAT_DBG("libc_accept4 socket fd:%d accept4\n", sockfd);
		accept_value = (*libc_accept4)(sockfd, addr, addrlen, flags);
	} else { /* pre init*/
		LIBC_FUNCTION(accept4);

		ECAT_DBG("libc_accept4 socket fd:%d accept4\n", sockfd);
		if (libc_accept4)
			accept_value = (*libc_accept4)(sockfd, addr,
					addrlen, flags);
		else {
			accept_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Accept4 called on socket '%d' returned:'%d'\n",
		sockfd, accept_value);*/
	return accept_value;
}

int listen(int sockfd, int backlog)
{
	int listen_value = -1;

	if (IS_USECT_SOCKET(sockfd)) {
		printf("DPDP socket fd:%d listen\n", sockfd);
		return 0;
	} else if (libc_listen) {
		ECAT_DBG("libc_socket fd:%d listen\n", sockfd);
		listen_value = (*libc_listen)(sockfd, backlog);
	} else { /* pre init*/
		LIBC_FUNCTION(listen);
		ECAT_DBG("libc_socket fd:%d listen\n", sockfd);

		if (libc_listen)
			listen_value = (*libc_listen)(sockfd, backlog);
		else {
			listen_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Listen called on socket '%d' returns:'%d'\n",
		sockfd, listen_value);*/
	return listen_value;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int connect_value;

	if (IS_USECT_SOCKET(sockfd)) {
		printf("DPDP socket fd:%d connect\n", sockfd);
		connect_value = 0;
	} else if (libc_connect) {
		ECAT_DBG("libc_connect fd:%d connect\n", sockfd);
		connect_value = (*libc_connect)(sockfd, addr, addrlen);
	} else {
		LIBC_FUNCTION(connect);
		ECAT_DBG("libc_connect fd:%d connect\n", sockfd);

		if (libc_connect)
			connect_value = (*libc_connect)(sockfd, addr, addrlen);
		else {
			connect_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Connect called on socket '%d' returns:'%d'\n",
		sockfd, connect_value);*/
	return connect_value;
}

ssize_t read(int sockfd, void *buf, size_t len)
{
	ssize_t read_value;

	if (IS_USECT_SOCKET(sockfd)) {
		ECAT_DBG("DPDP socket fd:%d read\n", sockfd);
		read_value = dpdk_recv(sockfd, buf, len, 0);
		errno = 0;
	} else if (libc_read) {
		ECAT_DBG("libc_read socket fd:%d read\n", sockfd);
		read_value = (*libc_read)(sockfd, buf, len);
	} else {
		LIBC_FUNCTION(read);
		ECAT_DBG("libc_read socket fd:%d read\n", sockfd);

		if (libc_read)
			read_value = (*libc_read)(sockfd, buf, len);
		else {
			read_value = -1;
			errno = EACCES;
		}
	}

	return read_value;
}

ssize_t write(int sockfd, const void *buf, size_t len)
{
	ssize_t write_value;

	if (IS_USECT_SOCKET(sockfd)) {
		ECAT_DBG("DPDP socket fd:%d write\n", sockfd);
		write_value = dpdk_send(sockfd, buf, len, 0);
		errno = 0;
	} else if (libc_write) {
		ECAT_DBG("libc_write socket fd:%d write\n", sockfd);
		write_value = (*libc_write)(sockfd, buf, len);
	} else {
		LIBC_FUNCTION(write);
		ECAT_DBG("libc_write socket fd:%d write\n", sockfd);
		if (libc_write)
			write_value = (*libc_write)(sockfd, buf, len);
		else {
			write_value = -1;
			errno = EACCES;
		}
	}

	return write_value;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t recv_value;

	if (IS_USECT_SOCKET(sockfd)) {
		ECAT_DBG("DPDP socket fd:%d recv\n", sockfd);
		recv_value = dpdk_recv(sockfd, buf, len, flags);
		errno = 0;
	} else if (libc_recv) {
		ECAT_DBG("libc_recv socket fd:%d recv\n", sockfd);
		recv_value = (*libc_recv)(sockfd, buf, len, flags);
	} else { /* pre init*/
		LIBC_FUNCTION(recv);
		ECAT_DBG("libc_recv socket fd:%d recv\n", sockfd);

		if (libc_recv) {
			recv_value = (*libc_recv)(sockfd, buf, len, flags);
		} else {
			recv_value = -1;
			errno = EACCES;
		}
	}

	return recv_value;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen)
{
	//ECAT_DBG("DPDP socket fd:%d recvfrom\n", sockfd);
	return recv(sockfd, buf, len, flags);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	ssize_t send_value;

	if (IS_USECT_SOCKET(sockfd)) {
		ECAT_DBG("DPDP socket fd:%d send\n", sockfd);
		send_value = dpdk_send(sockfd, buf, len, flags);
		errno = 0;
	} else if (libc_send) {
		ECAT_DBG("libc_send socket fd:%d send\n", sockfd);
		send_value = (*libc_send)(sockfd, buf, len, flags);
	} else {
		LIBC_FUNCTION(send);
		ECAT_DBG("libc_send socket fd:%d send\n", sockfd);

		if (libc_send) {
			send_value = (*libc_send)(sockfd, buf, len, flags);
		} else {
			send_value = -1;
			errno = EACCES;
		}
	}

	return send_value;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	//ECAT_DBG("DPDP socket fd:%d sendto\n", sockfd);
	return send(sockfd, buf, len, flags);
}
