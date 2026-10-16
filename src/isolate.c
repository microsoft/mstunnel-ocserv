/*
 * Copyright (C) 2013-2026 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2016 Red Hat, Inc.
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

#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <grp.h>
#include <worker.h>
#include <main.h>
#include <limits.h>
#include <unistd.h>

/*
 * Headroom above the measured data-segment baseline granted to each worker.
 * Takes into account max values for HTTP body+headers (256 + 128 KB),
 * presence of GnuTLS + worker I/O buffers + talloc/libc overhead +
 * safety margin = 64 MB total. */
#define WORKER_MEMORY_HEADROOM_KB (64 * 1024)

#ifdef __linux__
/* Returns a per-worker RLIMIT_DATA cap: data+stack baseline plus headroom.
 * Field 6 of /proc/self/statm ("data" = VmData+VmStk, in pages).
 * Returns 0 on any read failure (caller skips the limit).
 */
static rlim_t compute_worker_data_limit(unsigned headroom_kb)
{
	FILE *f;
	/* statm: size resident shared text lib data dt (all in pages) */
	unsigned long size, resident, shared, text, lib, data;
	int n;

	f = fopen("/proc/self/statm", "r");
	if (!f)
		return 0;

	n = fscanf(f, "%lu %lu %lu %lu %lu %lu", &size, &resident, &shared,
		   &text, &lib, &data);
	fclose(f);
	if (n != 6)
		return 0;

	return (rlim_t)data * (rlim_t)sysconf(_SC_PAGESIZE) +
	       (rlim_t)headroom_kb * 1024;
}

/* Apply per-worker heap cap (RLIMIT_DATA) unless explicitly disabled. */
void set_worker_mem_limits(struct worker_st *ws)
{
	struct rlimit rl;
	rlim_t lim;

	if (GETRCONFIG(ws)->has_limit_worker_memory &&
	    !GETRCONFIG(ws)->limit_worker_memory)
		return;

	lim = compute_worker_data_limit(WORKER_MEMORY_HEADROOM_KB);
	if (lim == 0) {
		oclog(ws, LOG_INFO,
		      "could not read memory baseline from "
		      "/proc/self/statm; skipping RLIMIT_DATA");
		return;
	}

	/* similarly to set_worker_fd_limits() this doesn't hard fail
	 * if we are unable to set the limit, as the limit may have been
	 * lowered for ocserv as a whole. */
	rl.rlim_cur = lim;
	rl.rlim_max = lim;
	if (setrlimit(RLIMIT_DATA, &rl) < 0) {
#ifdef WORKER_MEMORY_LIMIT_TEST
		oclog(ws, LOG_ERR, "could not set RLIMIT_DATA to %zu: %s",
		      (size_t)lim, strerror(errno));
		exit(EXIT_FAILURE);
#else
		oclog(ws, LOG_INFO, "could not set RLIMIT_DATA to %zu: %s",
		      (size_t)lim, strerror(errno));
#endif /* WORKER_MEMORY_LIMIT_TEST */
	}
}
#else /* !__linux__ */
void set_worker_mem_limits(struct worker_st *ws)
{
}
#endif /* __linux__ */

/* Adjusts the file descriptor limits for the worker processes
 */
void set_worker_fd_limits(struct worker_st *ws)
{
#ifdef RLIMIT_NOFILE
	struct rlimit def_set;
	int ret;

	ret = getrlimit(RLIMIT_NOFILE, &def_set);
	if (ret < 0) {
		int e = errno;

		oclog(ws, LOG_ERR, "error in getrlimit: %s", strerror(e));
		exit(EXIT_FAILURE);
	}

	ret = setrlimit(RLIMIT_NOFILE, &def_set);
	if (ret < 0) {
		oclog(ws, LOG_INFO, "cannot update file limit(%u): %s",
		      (unsigned int)def_set.rlim_cur, strerror(errno));
	}
#endif
}

void drop_privileges(struct worker_st *ws, main_server_st *s)
{
	int ret, e;
	struct rlimit rl;

	if (GETSCONFIG(s)->chroot_dir) {
		ret = chdir(GETSCONFIG(s)->chroot_dir);
		if (ret != 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot chdir to %s: %s",
			      GETSCONFIG(s)->chroot_dir, strerror(e));
			exit(EXIT_FAILURE);
		}

		ret = chroot(GETSCONFIG(s)->chroot_dir);
		if (ret != 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot chroot to %s: %s",
			      GETSCONFIG(s)->chroot_dir, strerror(e));
			exit(EXIT_FAILURE);
		}

		ret = chdir("/");
		if (ret != 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot chdir to '/': %s",
			      strerror(e));
			exit(EXIT_FAILURE);
		}
	}

	if (GETSCONFIG(s)->gid != -1 && (getgid() == 0 || getegid() == 0)) {
		ret = setgid(GETSCONFIG(s)->gid);
		if (ret < 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot set gid to %d: %s",
			      (int)GETSCONFIG(s)->gid, strerror(e));
			exit(EXIT_FAILURE);
		}

		ret = setgroups(1, &GETSCONFIG(s)->gid);
		if (ret < 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot set groups to %d: %s",
			      (int)GETSCONFIG(s)->gid, strerror(e));
			exit(EXIT_FAILURE);
		}
	}

	if (GETSCONFIG(s)->uid != -1 && (getuid() == 0 || geteuid() == 0)) {
		ret = setuid(GETSCONFIG(s)->uid);
		if (ret < 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot set uid to %d: %s",
			      (int)GETSCONFIG(s)->uid, strerror(e));
			exit(EXIT_FAILURE);
		}
	}

	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	ret = setrlimit(RLIMIT_NPROC, &rl);
	if (ret < 0) {
		e = errno;
		oclog(ws, LOG_ERR, "cannot enforce NPROC limit: %s",
		      strerror(e));
	}
}
