/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
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
 * LD_PRELOAD shim that intercepts openlog(3) and appends the facility name
 * (one per line) to the file named by $SYSLOG_SHIM_OUT.
 *
 * Used by test-syslog-facility to verify that ocserv passes the configured
 * syslog facility to openlog() without requiring a real syslog daemon.
 * Multiple processes (main + worker) call openlog(); the test uses grep to
 * confirm the expected facility appears at least once.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

static const char *facility_name(int facility)
{
	switch (facility) {
	case LOG_DAEMON:
		return "daemon";
	case LOG_USER:
		return "user";
	case LOG_AUTH:
		return "auth";
	case LOG_LOCAL0:
		return "local0";
	case LOG_LOCAL1:
		return "local1";
	case LOG_LOCAL2:
		return "local2";
	case LOG_LOCAL3:
		return "local3";
	case LOG_LOCAL4:
		return "local4";
	case LOG_LOCAL5:
		return "local5";
	case LOG_LOCAL6:
		return "local6";
	case LOG_LOCAL7:
		return "local7";
#ifdef LOG_AUTHPRIV
	case LOG_AUTHPRIV:
		return "authpriv";
#endif
	default:
		return "unknown";
	}
}

void openlog(const char *ident, int logopt, int facility)
{
	static void (*real_openlog)(const char *, int, int);
	const char *out;
	FILE *f;

	out = getenv("SYSLOG_SHIM_OUT");
	if (out != NULL) {
		f = fopen(out, "a");
		if (f != NULL) {
			fprintf(f, "%s\n", facility_name(facility));
			fclose(f);
		}
	}

	if (real_openlog == NULL)
		real_openlog = dlsym(RTLD_NEXT, "openlog");
	if (real_openlog != NULL)
		real_openlog(ident, logopt, facility);
}
