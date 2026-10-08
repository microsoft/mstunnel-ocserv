/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef OC_WORKER_TUN_H
#define OC_WORKER_TUN_H

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
ssize_t tun_write(int sockfd, const void *buf, size_t len);
ssize_t tun_read(int sockfd, void *buf, size_t len);
#else
#define tun_write write
#define tun_read read
#endif

#ifndef __FreeBSD__
#define tun_claim(sockfd) 0
#else
/*
 * FreeBSD has a mechanism by which a tunnel has a single controlling process,
 * and only that one process may close it.  When the controlling process closes
 * the tunnel, the state is torn down.
 */
static int tun_claim(int sockfd)
{
	return ioctl(sockfd, TUNSIFPID, 0);
}
#endif /* !__FreeBSD__ */

#endif
