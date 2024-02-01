#include "netwrap_common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "netwrap_ioctl.h"
#include "netwrap_errno.h"
#include "netwrap_log.h"
#include "netwrap_common.h"

extern struct packet_info pinfo;
static int (*libc_ioctl)(int, unsigned long int, ...);

void setup_ioctl_wrappers(void)
{
	LIBC_FUNCTION(ioctl);
}

int ioctl(int fd, unsigned long int request, ...)
{
	int ioctl_value;
	va_list ap;
	void *data;

	va_start(ap, request);
	data = va_arg(ap, void *);
	va_end(ap);

	if (IS_USECT_SOCKET(fd)) {
		printf("DPDK IOCTL fd = %d, request = 0x%lx\n",
				fd, request);
		ioctl_value = (*libc_ioctl)(fd, request, data);
	} else if (libc_ioctl) {
		ECAT_DBG("libc_ioctl fd = %d, request = 0x%x\n",
				fd, request);
		ioctl_value = (*libc_ioctl)(fd, request, data);
	} else {
		LIBC_FUNCTION(ioctl);
		ECAT_DBG("libc_ioctl fd = %d, request = 0x%x\n",
				fd, request);
		if (libc_ioctl)
			ioctl_value = (*libc_ioctl)(fd, request, data);
		else {
			ioctl_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Ioctl called on socket '%d' returned %d\n", fd,
		ioctl_value);*/
	return ioctl_value;
}

int netwrap_get_dst_hw(int sockfd, struct sockaddr_in *ia)
{
	int ret;
	struct arpreq arpreq;
	char *ifname = getenv("ETH_NAME");

	memset(&arpreq, 0, sizeof(struct arpreq));
	memcpy(&arpreq.arp_pa, ia, sizeof(struct sockaddr_in));
	strcpy(arpreq.arp_dev, ifname);
	arpreq.arp_pa.sa_family = AF_INET;
	arpreq.arp_ha.sa_family = AF_UNSPEC;

	if (!libc_ioctl) {
		printf("libc_ioctl is NULL\n");
		return -1;
	}

	ret = (*libc_ioctl)(sockfd, SIOCGARP, &arpreq);
	if (ret < 0) {
		printf("ioctl SIOCGARP error: %d\n", ret);
		return ret;
	}

	memcpy(&pinfo.dst_mac, &arpreq.arp_ha.sa_data, sizeof(pinfo.dst_mac));
	printf("DPDK socket fd:%d, Dst Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		sockfd, pinfo.dst_mac[0], pinfo.dst_mac[1], pinfo.dst_mac[2],
		pinfo.dst_mac[3], pinfo.dst_mac[4], pinfo.dst_mac[5]);

	return 0;
}

int netwrap_get_local_hw(int sockfd)
{
	int ret;
	struct ifreq ifr;
	char *ifname = getenv("ETH_NAME");

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (!libc_ioctl) {
		printf("libc_ioctl is NULL\n");
		return -1;
	}

	ret = (*libc_ioctl)(sockfd, SIOCGIFHWADDR, &ifr);
	if (ret < 0) {
		printf("ioctl SIOCGIFHWADDR error:%d\n", ret);
		return ret;
	}

	memcpy(&pinfo.src_mac, &ifr.ifr_hwaddr.sa_data, sizeof(pinfo.src_mac));
	printf("DPDK socket fd:%d, Local Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		sockfd, pinfo.src_mac[0], pinfo.src_mac[1], pinfo.src_mac[2],
		pinfo.src_mac[3], pinfo.src_mac[4], pinfo.src_mac[5]);

	return 0;
}

