/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <cloexec.h>
#include <ip-lease.h>

#if defined(HAVE_LINUX_IF_TUN_H)
#include <linux/if_tun.h>
#elif defined(HAVE_NET_IF_TUN_H)
#include <net/if_tun.h>
#endif

#include <netdb.h>
#include <vpn.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>
#include "vhost.h"
#include "log.h"

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#include <net/if_var.h>
#include <netinet/in_var.h>
#endif
#if defined(__OpenBSD__)
#include <netinet6/in6_var.h>
#endif
#if defined(__DragonFly__)
#include <net/tun/if_tun.h>
#endif

#if defined(__OpenBSD__) || defined(TUNSIFHEAD)
#define TUN_AF_PREFIX 1
#endif

#ifdef TUN_AF_PREFIX
ssize_t tun_write(int sockfd, const void *buf, size_t len)
{
	struct ip *iph = (void *)buf;
	uint32_t head;
	const uint8_t *data = buf;
	static int complained;
	struct iovec iov[2];
	int ret;

	if (iph->ip_v == 6)
		head = htonl(AF_INET6);
	else if (iph->ip_v == 4)
		head = htonl(AF_INET);
	else {
		if (!complained) {
			complained = 1;
			oc_syslog(
				LOG_ERR,
				"tun_write: Unknown packet (len %d) received %02x %02x %02x %02x...\n",
				(int)len, data[0], data[1], data[2], data[3]);
		}
		return -1;
	}

	iov[0].iov_base = &head;
	iov[0].iov_len = sizeof(head);
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = len;

	ret = writev(sockfd, iov, 2);
	if (ret >= sizeof(uint32_t))
		ret -= sizeof(uint32_t);
	return ret;
}

ssize_t tun_read(int sockfd, void *buf, size_t len)
{
	uint32_t head;
	struct iovec iov[2];
	int ret;

	iov[0].iov_base = &head;
	iov[0].iov_len = sizeof(head);
	iov[1].iov_base = buf;
	iov[1].iov_len = len;

	ret = readv(sockfd, iov, 2);
	if (ret >= sizeof(uint32_t))
		ret -= sizeof(uint32_t);
	return ret;
}

#else
ssize_t tun_write(int sockfd, const void *buf, size_t len)
{
	return force_write(sockfd, buf, len);
}

ssize_t tun_read(int sockfd, void *buf, size_t len)
{
	return read(sockfd, buf, len);
}
#endif

#ifndef __FreeBSD__
int tun_claim(int sockfd)
{
	return 0;
}
#else
/*
 * FreeBSD has a mechanism by which a tunnel has a single controlling process,
 * and only that one process may close it.  When the controlling process closes
 * the tunnel, the state is torn down.
 */
int tun_claim(int sockfd)
{
	return ioctl(sockfd, TUNSIFPID, 0);
}
#endif /* !__FreeBSD__ */
