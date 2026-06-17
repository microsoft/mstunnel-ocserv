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

/* This global variable is used by oc_syslog() */
int global_log_prio = DEFAULT_LOG_LEVEL;

void __attribute__((format(printf, 2, 3))) oc_syslog(int priority,
						     const char *fmt, ...)
{
	char buf[512];
	va_list args;
	int syslog_prio;

	if (!log_check_priority(priority, global_log_prio, &syslog_prio))
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	_oc_syslog(syslog_prio, "%s", buf);
}
