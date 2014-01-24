/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2013 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <assert.h>  /* assert(3), */
#include <stdint.h>  /* intptr_t, */
#include <errno.h>   /* E*, */
#include <sys/stat.h>   /* chmod(2), stat(2) */
#include <sys/types.h>  /* uid_t, gid_t */
#include <unistd.h>  /* get*id(2),  */
#include <sys/ptrace.h>    /* linux.git:c0a3a20b  */
#include <linux/audit.h>   /* AUDIT_ARCH_*,  */
#include <string.h>  /* memcpy(3) */

#include "cli/notice.h"
#include "extension/extension.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "tracee/tracee.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "path/binding.h"
#include "arch.h"


/* List of syscalls handled by this extensions.  */
static FilteredSysnum filtered_sysnums[] = {
	{ PR_access,		FILTER_SYSEXIT },
	{ PR_brk,		FILTER_SYSEXIT },
	{ PR_capset,		FILTER_SYSEXIT },
	{ PR_chmod,		FILTER_SYSEXIT },
	{ PR_chown,		FILTER_SYSEXIT },
	{ PR_chown32,		FILTER_SYSEXIT },
	{ PR_chroot,		FILTER_SYSEXIT },
	{ PR_close,		FILTER_SYSEXIT },
	{ PR_fchmod,		FILTER_SYSEXIT },
	{ PR_fchmodat,		FILTER_SYSEXIT },
	{ PR_fchown,		FILTER_SYSEXIT },
	{ PR_fchown32,		FILTER_SYSEXIT },
	{ PR_fchownat,		FILTER_SYSEXIT },
	{ PR_fchownat,		FILTER_SYSEXIT },
	{ PR_fstat,		FILTER_SYSEXIT },
	{ PR_fstat,		FILTER_SYSEXIT },
	{ PR_fstat64,		FILTER_SYSEXIT },
	{ PR_fstatat64,		FILTER_SYSEXIT },
	{ PR_getegid,		FILTER_SYSEXIT },
	{ PR_getegid32,		FILTER_SYSEXIT },
	{ PR_geteuid,		FILTER_SYSEXIT },
	{ PR_geteuid32,		FILTER_SYSEXIT },
	{ PR_getgid,		FILTER_SYSEXIT },
	{ PR_getgid32,		FILTER_SYSEXIT },
	{ PR_getresgid,		FILTER_SYSEXIT },
	{ PR_getresgid32,	FILTER_SYSEXIT },
	{ PR_getresuid,		FILTER_SYSEXIT },
	{ PR_getresuid32,	FILTER_SYSEXIT },
	{ PR_getuid,		FILTER_SYSEXIT },
	{ PR_getuid32,		FILTER_SYSEXIT },
	{ PR_lchown,		FILTER_SYSEXIT },
	{ PR_lchown32,		FILTER_SYSEXIT },
	{ PR_lstat,		FILTER_SYSEXIT },
	{ PR_lstat64,		FILTER_SYSEXIT },
	{ PR_mknod,		FILTER_SYSEXIT },
	{ PR_newfstatat,	FILTER_SYSEXIT },
	{ PR_oldlstat,		FILTER_SYSEXIT },
	{ PR_oldstat,		FILTER_SYSEXIT },
	{ PR_open,		FILTER_SYSEXIT },
	{ PR_openat,		FILTER_SYSEXIT },
	{ PR_read,		FILTER_SYSEXIT },
	{ PR_setfsgid,		FILTER_SYSEXIT },
	{ PR_setfsgid32,	FILTER_SYSEXIT },
	{ PR_setfsuid,		FILTER_SYSEXIT },
	{ PR_setfsuid32,	FILTER_SYSEXIT },
	{ PR_setgid,		FILTER_SYSEXIT },
	{ PR_setgid32,		FILTER_SYSEXIT },
	{ PR_setgroups,		FILTER_SYSEXIT },
	{ PR_setgroups32,	FILTER_SYSEXIT },
	{ PR_setregid,		FILTER_SYSEXIT },
	{ PR_setregid32,	FILTER_SYSEXIT },
	{ PR_setreuid,		FILTER_SYSEXIT },
	{ PR_setreuid32,	FILTER_SYSEXIT },
	{ PR_setresgid,		FILTER_SYSEXIT },
	{ PR_setresgid32,	FILTER_SYSEXIT },
	{ PR_setresuid,		FILTER_SYSEXIT },
	{ PR_setresuid32,	FILTER_SYSEXIT },
	{ PR_setuid,		FILTER_SYSEXIT },
	{ PR_setuid32,		FILTER_SYSEXIT },
	{ PR_setxattr,		FILTER_SYSEXIT },
	{ PR_stat,		FILTER_SYSEXIT },
	{ PR_stat64,		FILTER_SYSEXIT },
	{ PR_statfs,		FILTER_SYSEXIT },
	{ PR_statfs64,		FILTER_SYSEXIT },
	FILTERED_SYSNUM_END,
};


static void pstrace_print(const char *psz_name, int result, const char *psz_fmt, ...)
{
	va_list args;
	va_start(args, psz_fmt);

	printf("\e[1m%s\e[0m(", psz_name);
	vprintf(psz_fmt, args);
	printf(") = \e[1;%dm%d\e[0m\n", result < 0 ? 31 : 32, result);
}

/**
 * Print the syscall and the values that where passed and will be returned
 * This function returns -errno if an error occured, otherwise 0.
 */
static int handle_sysexit_end(Tracee *tracee)
{
  char path[PATH_MAX];
  int result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	word_t sysnum;

	sysnum = get_sysnum(tracee, ORIGINAL);

	switch (sysnum) {
  case PR_access: {
		get_sysarg_path(tracee, path, SYSARG_1);
		pstrace_print("access", result, "\"%s\"", path);
		return 0;
  }

	case PR_brk: {
		void *addr = (void*) peek_reg(tracee, CURRENT, SYSARG_1);
		if (addr == NULL)
			pstrace_print("brk", result, "0");
		else
			pstrace_print("brk", result, "%p", addr);
		return 0;
	}

	case PR_close: {
		int fd = peek_reg(tracee, CURRENT, SYSARG_1);
		pstrace_print("close", result, "%d", fd);
		return 0;
	}

	case PR_fstat: {
		int fd = peek_reg(tracee, CURRENT, SYSARG_1);
		pstrace_print("fstat", result, "%d", fd);
		return 0;
	}

  case PR_open: {
		get_sysarg_path(tracee, path, SYSARG_1);
		pstrace_print("open", result, "\"%s\"", path);
		return 0;
	}

	case PR_openat: {
		int dirfd = peek_reg(tracee, CURRENT, SYSARG_1);
		get_sysarg_path(tracee, path, SYSARG_2);
		if(dirfd == AT_FDCWD)
			pstrace_print("openat", result, "AT_FDCWD, \"%s\"", path);
		else
			pstrace_print("openat", result, "%d, \"%s\"", dirfd, path);
		return 0;
	}

	case PR_read: {
		int fd = peek_reg(tracee, CURRENT, SYSARG_1);
		void * buf = (void *)peek_reg(tracee, CURRENT, SYSARG_2);
		size_t count = peek_reg(tracee, CURRENT, SYSARG_3);
		pstrace_print("read", result, "%d, %p, %zu", fd, buf, count);
		return 0;
	}

	default:
		return 0;
	}
}


/**
 * Handler for this @extension.  It is triggered each time an @event
 * occurred.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int pstrace_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2)
{
	(void)data1;
	(void)data2;

	switch (event) {
	case INITIALIZATION:
		extension->filtered_sysnums = filtered_sysnums;
		return 0;

	case INHERIT_PARENT: /* Inheritable for sub reconfiguration ...  */
		return 1;

	case SYSCALL_EXIT_END: {
		Tracee *tracee = TRACEE(extension);

		return handle_sysexit_end(tracee);
	}

	default:
		return 0;
	}
}
