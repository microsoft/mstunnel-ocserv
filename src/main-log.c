/*
 * Copyright (C) 2013-2023 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <base64-helper.h>

#include <worker.h>
#include <main.h>
#include "sec-mod.h"
#include "log.h"

/* proc is optional */
void __attribute__((format(printf, 4, 5))) _mslog(const main_server_st *s,
						  const struct proc_st *proc,
						  int priority, const char *fmt,
						  ...)
{
	char buf[512];
	char ipbuf[128];
	char name[MAX_USERNAME_SIZE + MAX_HOSTNAME_SIZE + 3];
	const char *ip = NULL;
	va_list args;
	int log_prio = DEFAULT_LOG_LEVEL;
	unsigned int have_vhosts;
	int syslog_prio;

	if (s)
		log_prio = GETPCONFIG(s)->log_level;

	if (!log_check_priority(priority, log_prio, &syslog_prio))
		return;

	if (proc) {
		ip = human_addr((void *)&proc->remote_addr,
				proc->remote_addr_len, ipbuf, sizeof(ipbuf));
	} else {
		ip = "";
	}

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	have_vhosts = s ? HAVE_VHOSTS(s) : 0;

	if (have_vhosts && proc && proc->username[0] != 0) {
		snprintf(name, sizeof(name), "[%s%s]",
			 PREFIX_VHOST(proc->vhost), proc->username);
	} else if (have_vhosts && proc && proc->username[0] == 0 &&
		   proc->vhost && proc->vhost->name) {
		snprintf(name, sizeof(name), "[vhost:%s]",
			 VHOSTNAME(proc->vhost));
	} else if (proc && proc->username[0] != 0) {
		snprintf(name, sizeof(name), "[%s]", proc->username);
	} else
		name[0] = 0;

	_oc_syslog(syslog_prio, "main%s:%s %s", name, ip ? ip : "[unknown]",
		   buf);
}

void mslog_hex(const main_server_st *s, const struct proc_st *proc,
	       int priority, const char *prefix, uint8_t *bin,
	       unsigned int bin_size, unsigned int b64)
{
	char buf[512];
	int ret;
	size_t buf_size;
	gnutls_datum_t data = { bin, bin_size };
	int log_prio = DEFAULT_LOG_LEVEL;

	if (s)
		log_prio = GETPCONFIG(s)->log_level;

	if (!log_check_priority(priority, log_prio, NULL))
		return;

	if (b64) {
		oc_base64_encode((char *)bin, bin_size, (char *)buf,
				 sizeof(buf));
	} else {
		buf_size = sizeof(buf);
		ret = gnutls_hex_encode(&data, buf, &buf_size);
		if (ret < 0)
			return;
	}

	_mslog(s, proc, priority, "%s %s", prefix, buf);
}

void seclog_hex(const struct sec_mod_st *sec, int priority, const char *prefix,
		uint8_t *bin, unsigned int bin_size, unsigned int b64)
{
	char buf[512];
	int ret;
	size_t buf_size;
	gnutls_datum_t data = { bin, bin_size };
	int log_prio;

	log_prio = GETPCONFIG(sec)->log_level;

	if (!log_check_priority(priority, log_prio, NULL))
		return;

	if (b64) {
		oc_base64_encode((char *)bin, bin_size, (char *)buf,
				 sizeof(buf));
	} else {
		buf_size = sizeof(buf);
		ret = gnutls_hex_encode(&data, buf, &buf_size);
		if (ret < 0)
			return;
	}

	seclog(sec, priority, "%s %s", prefix, buf);
}

void __attribute__((format(printf, 3, 4)))
_seclog(const sec_mod_st *sec, int priority, const char *fmt, ...)
{
	char buf[512];
	va_list args;
	int log_prio = DEFAULT_LOG_LEVEL;
	int syslog_prio;

	if (sec)
		log_prio = GETPCONFIG(sec)->log_level;

	if (!log_check_priority(priority, log_prio, &syslog_prio))
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	_oc_syslog(syslog_prio, "sec-mod: %s", buf);
}
