/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
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
#ifndef PAM_STACK_H
#define PAM_STACK_H

#include <config.h>
#include <stdlib.h>
#ifdef __linux__
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

/* Minimum coroutine stack; lower values caused silent heap corruption
 * (#619, #657).  The actual size is read from RLIMIT_STACK at runtime. */
#define MIN_PAM_STACK_SIZE (8 * 1024 * 1024)

struct pam_stack_st {
	void *base; /* mmap base (Linux) or malloc'd pointer */
#ifdef __linux__
	size_t total; /* total mmap size: guard page + usable area */
#endif
};

/* Returns the coroutine stack size: RLIMIT_STACK if it is finite and at
 * least MIN_PAM_STACK_SIZE, otherwise MIN_PAM_STACK_SIZE. */
static inline size_t pam_stack_size(void)
{
#ifdef __linux__
	struct rlimit rl;
	if (getrlimit(RLIMIT_STACK, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY &&
	    rl.rlim_cur >= MIN_PAM_STACK_SIZE)
		return (size_t)rl.rlim_cur;
#endif
	return MIN_PAM_STACK_SIZE;
}

#ifdef __linux__
/* Returns the usable stack base to pass to co_create, storing the full mmap
 * region in st for cleanup.  Returns NULL on failure (PCL falls back to
 * malloc). */
static inline void *pam_stack_alloc(struct pam_stack_st *st, size_t size)
{
	long pgsz = sysconf(_SC_PAGESIZE);
	size_t total;
	void *map;

	if (pgsz <= 0)
		return NULL;
	total = (size_t)pgsz + size;
	map = mmap(NULL, total, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (map == MAP_FAILED)
		return NULL;
	/* Guard page below the stack: overflow → SIGSEGV, not silent heap corruption. */
	if (mprotect(map, (size_t)pgsz, PROT_NONE) != 0) {
		munmap(map, total);
		return NULL;
	}
	st->base = map;
	st->total = total;
	return (char *)map + pgsz;
}

static inline void pam_stack_free(struct pam_stack_st *st)
{
	if (st->base != NULL) {
		munmap(st->base, st->total);
		st->base = NULL;
	}
}
#else /* !__linux__ */
static inline void *pam_stack_alloc(struct pam_stack_st *st, size_t size)
{
	st->base = malloc(size);
	return st->base;
}
static inline void pam_stack_free(struct pam_stack_st *st)
{
	free(st->base);
	st->base = NULL;
}
#endif /* __linux__ */

#endif /* PAM_STACK_H */
