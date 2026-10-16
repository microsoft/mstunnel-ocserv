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
#include "gnulib/cloexec.h"
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
#include "worker-tun.h"

#ifdef TUN_AF_PREFIX
/* BSD-specific code, in linux tun_write and tun_read are
 * just write and read. */
ssize_t tun_write(int sockfd, const void *buf, size_t len)
{
	uint32_t head;
	const uint8_t *data = buf;
	uint8_t ip_v;
	static int complained;
	struct iovec iov[2];
	int ret;

	if (len == 0)
		return 0;

	ip_v = data[0] >> 4;

	if (ip_v == 6)
		head = htonl(AF_INET6);
	else if (ip_v == 4)
		head = htonl(AF_INET);
	else {
		if (!complained) {
			complained = 1;
			oc_syslog(LOG_ERR, "tun_write: Unknown packet (len %d)",
				  (int)len);
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
#endif
