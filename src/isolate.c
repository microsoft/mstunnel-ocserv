/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
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
#include <sys/resource.h>
#include <grp.h>
#include <main.h>
#include <limits.h>

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

		oclog(ws, LOG_ERR, "error in getrlimit: %s\n", strerror(e));
		exit(EXIT_FAILURE);
	}

	ret = setrlimit(RLIMIT_NOFILE, &def_set);
	if (ret < 0) {
		oclog(ws, LOG_INFO, "cannot update file limit(%u): %s\n",
		      (unsigned int)def_set.rlim_cur, strerror(errno));
	}
#endif
}

void drop_privileges(struct worker_st *ws, main_server_st *s)
{
	int ret, e;
	struct rlimit rl;

	if (GETPCONFIG(s)->chroot_dir) {
		ret = chdir(GETPCONFIG(s)->chroot_dir);
		if (ret != 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot chdir to %s: %s",
			      GETPCONFIG(s)->chroot_dir, strerror(e));
			exit(EXIT_FAILURE);
		}

		ret = chroot(GETPCONFIG(s)->chroot_dir);
		if (ret != 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot chroot to %s: %s",
			      GETPCONFIG(s)->chroot_dir, strerror(e));
			exit(EXIT_FAILURE);
		}
	}

	if (GETPCONFIG(s)->gid != -1 && (getgid() == 0 || getegid() == 0)) {
		ret = setgid(GETPCONFIG(s)->gid);
		if (ret < 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot set gid to %d: %s\n",
			      (int)GETPCONFIG(s)->gid, strerror(e));
			exit(EXIT_FAILURE);
		}

		ret = setgroups(1, &GETPCONFIG(s)->gid);
		if (ret < 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot set groups to %d: %s\n",
			      (int)GETPCONFIG(s)->gid, strerror(e));
			exit(EXIT_FAILURE);
		}
	}

	if (GETPCONFIG(s)->uid != -1 && (getuid() == 0 || geteuid() == 0)) {
		ret = setuid(GETPCONFIG(s)->uid);
		if (ret < 0) {
			e = errno;
			oclog(ws, LOG_ERR, "cannot set uid to %d: %s\n",
			      (int)GETPCONFIG(s)->uid, strerror(e));
			exit(EXIT_FAILURE);
		}
	}

	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	ret = setrlimit(RLIMIT_NPROC, &rl);
	if (ret < 0) {
		e = errno;
		oclog(ws, LOG_ERR, "cannot enforce NPROC limit: %s\n",
		      strerror(e));
	}
}
