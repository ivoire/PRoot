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
#include <sys/ptrace.h>	/* linux.git:c0a3a20b  */
#include <linux/audit.h>   /* AUDIT_ARCH_*,  */
#include <string.h>  /* memcpy(3) */

#include "cli/notice.h"
#include "extension/extension.h"
#include "extension/pstrace/flags.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "tracee/tracee.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "path/binding.h"
#include "arch.h"


typedef struct {
	pid_t last_pid;
} Config;

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
	{ PR_connect,		FILTER_SYSEXIT },
	{ PR_execve,		FILTER_SYSEXIT },
	{ PR_exit_group,		FILTER_SYSEXIT },
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
	{ PR_getsockopt,	FILTER_SYSEXIT },
	{ PR_getuid,		FILTER_SYSEXIT },
	{ PR_getuid32,		FILTER_SYSEXIT },
	{ PR_lchown,		FILTER_SYSEXIT },
	{ PR_lchown32,		FILTER_SYSEXIT },
	{ PR_lseek,		FILTER_SYSEXIT },
	{ PR_lstat,		FILTER_SYSEXIT },
	{ PR_lstat64,		FILTER_SYSEXIT },
	{ PR_mkdir,		FILTER_SYSEXIT },
	{ PR_mknod,		FILTER_SYSEXIT },
	{ PR_mmap,		FILTER_SYSEXIT },
	{ PR_mprotect,		FILTER_SYSEXIT },
	{ PR_munmap,		FILTER_SYSEXIT },
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
	{ PR_unlink,		FILTER_SYSEXIT },
	{ PR_write,		FILTER_SYSEXIT },
	FILTERED_SYSNUM_END,
};


static void pstrace_print(Tracee *tracee, Config *config, const char *psz_fmt, ...)
{
	va_list args;
	va_start(args, psz_fmt);

	if (config->last_pid == tracee->pid) {
		printf("\e[36m  |  \e[0m");
	} else {
		printf("\e[36m%5d\e[0m", tracee->pid);
	}
	printf(" \e[1m%s\e[0m(", stringify_sysnum(get_sysnum(tracee, ORIGINAL)));
	vprintf(psz_fmt, args);
	printf(")");
}

#define PRINT(psz_fmt, args...) pstrace_print(tracee, config, psz_fmt, ## args)

static void ors2string(const value_string_t available_flags[],
	                   int flags, char psz_buffer[])
{
  int index = 0;
  bool is_first = true;

  while (available_flags[index].psz != NULL) {
	if (flags & available_flags[index].value) {
	  if (is_first) {
	    psz_buffer += sprintf(psz_buffer, "%s", available_flags[index].psz);
	    is_first = false;
	  }
	  else {
	    psz_buffer += sprintf(psz_buffer, " | %s", available_flags[index].psz);
	  }
	}
	index++;
  }
}

static int handle_sysenter_end(Tracee *tracee, Config *config)
{
	char path[PATH_MAX];
	word_t sysnum = get_sysnum(tracee, ORIGINAL);

	switch (sysnum) {
	case PR_access: {
		get_sysarg_path(tracee, path, SYSARG_1);
		int mode = peek_reg(tracee, CURRENT, SYSARG_2);
		if (mode == F_OK)
			PRINT("\"%s\", F_OK", path);
		else {
			char psz_mode[19];
			ors2string(access_flags, mode, psz_mode);
			PRINT("\"%s\", %s", path, psz_mode);
		}
		break;
	}

	case PR_brk: {
		void *addr = (void*) peek_reg(tracee, CURRENT, SYSARG_1);
		if (addr == NULL)
			PRINT("0");
		else
			PRINT("%p", addr);
		break;
	}

	case PR_close: {
		int fd = peek_reg(tracee, CURRENT, SYSARG_1);
		readlink_proc_pid_fd(tracee->pid, fd, path);
		PRINT("%d [%s]", fd, path);
		break;
	}

	case PR_execve: {
		get_sysarg_path(tracee, path, SYSARG_1);
		PRINT("\"%s\"", path);
		break;
	}

	case PR_exit_group: {
		int status = peek_reg(tracee, CURRENT, SYSARG_1);

		PRINT("%d", status);
		break;
	}

	case PR_fstat: {
		int fd = peek_reg(tracee, CURRENT, SYSARG_1);
		readlink_proc_pid_fd(tracee->pid, fd, path);
		word_t buf = peek_reg(tracee, CURRENT, SYSARG_2);
		PRINT("%d [%s], @%p", fd, path, (void *)buf);
		break;
	}

	case PR_lseek: {
		int fd = peek_reg(tracee, CURRENT, SYSARG_1);
		readlink_proc_pid_fd(tracee->pid, fd, path);
		off_t offset = peek_reg(tracee, CURRENT, SYSARG_2);
		int whence = peek_reg(tracee, CURRENT, SYSARG_3);

		const char* psz_whence = "???";
		switch (whence) {
		case SEEK_SET: psz_whence = "SEEK_SET"; break;
		case SEEK_CUR: psz_whence = "SEEK_CUR"; break;
		case SEEK_END: psz_whence = "SEEK_END"; break;
		case SEEK_DATA: psz_whence = "SEEK_DATA"; break;
		case SEEK_HOLE: psz_whence = "SEEK_HOLE"; break;
		}
		PRINT("%d [%s], %d, %s", fd, path, offset, psz_whence);
		break;
	}

	case PR_mmap: {
		void *addr = (void*)peek_reg(tracee, CURRENT, SYSARG_1);
		size_t length = peek_reg(tracee, CURRENT, SYSARG_2);
		char psz_prot[100];
		int prot = peek_reg(tracee, CURRENT, SYSARG_3);
		ors2string(mmap_prots, prot, psz_prot);

		char psz_flags[1000];
		int flags = peek_reg(tracee, CURRENT, SYSARG_4);
		ors2string(mmap_flags, flags, psz_flags);

		int fd = peek_reg(tracee, CURRENT, SYSARG_5);
		if (fd > 0)
			readlink_proc_pid_fd(tracee->pid, fd, path);
		else
			path[0] = '\0';
		off_t offset = peek_reg(tracee, CURRENT, SYSARG_6);

		if (addr != NULL)
			PRINT("%p, %zu, %s, %s, %d [%s], 0x%x", addr, length, psz_prot, psz_flags,
					fd, path, offset);
		else
			PRINT("NULL, %zu, %s, %s, %d [%s], 0x%x", length, psz_prot, psz_flags,
					fd, path, offset);
		break;
	}

	case PR_mprotect: {
		void *addr = (void*)peek_reg(tracee, CURRENT, SYSARG_1);
		size_t len = peek_reg(tracee, CURRENT, SYSARG_2);
		int prot = peek_reg(tracee, CURRENT, SYSARG_3);

		char psz_prot[100];
		sprintf(psz_prot, "PROT_NONE");
		ors2string(mmap_prots, prot, psz_prot);

		PRINT("%p, %zu, %s", addr, len, psz_prot);
		break;
	}

	case PR_munmap: {
		void *addr = (void*) peek_reg(tracee, CURRENT, SYSARG_1);
		size_t length = peek_reg(tracee, CURRENT, SYSARG_2);

		PRINT("%p, %zu", addr, length);
		break;
	}

	case PR_open: {
		//TODO: handle O_RDONLY
		get_sysarg_path(tracee, path, SYSARG_1);
		char psz_mode[1024] = {0};
		int mode = peek_reg(tracee, CURRENT, SYSARG_2);
		ors2string(open_flags, mode, psz_mode);
		PRINT("\"%s\", %s", path, psz_mode);
		break;
	}

	case PR_openat: {
		int dirfd = peek_reg(tracee, CURRENT, SYSARG_1);
		get_sysarg_path(tracee, path, SYSARG_2);

		char psz_mode[1024] = {0};
		int mode = peek_reg(tracee, CURRENT, SYSARG_3);
		ors2string(open_flags, mode, psz_mode);

		if(dirfd == AT_FDCWD)
			PRINT("AT_FDCWD, \"%s\", %s", path, psz_mode);
		else
			PRINT("%d, \"%s\", %s", dirfd, path, psz_mode);
		break;
	}

	case PR_read: {
		int fd = peek_reg(tracee, CURRENT, SYSARG_1);
		void * buf = (void *)peek_reg(tracee, CURRENT, SYSARG_2);
		size_t count = peek_reg(tracee, CURRENT, SYSARG_3);
		readlink_proc_pid_fd(tracee->pid, fd, path);
		PRINT("%d [%s], @%p, %zu", fd, path, buf, count);
		break;
	}

	case PR_stat:
	case PR_statfs: {
		get_sysarg_path(tracee, path, SYSARG_1);
		PRINT("\"%s\"", path);
		break;
	}

	case PR_write: {
		int fd = peek_reg(tracee, CURRENT, SYSARG_1);
		void * buf = (void *)peek_reg(tracee, CURRENT, SYSARG_2);
		size_t count = peek_reg(tracee, CURRENT, SYSARG_3);
		readlink_proc_pid_fd(tracee->pid, fd, path);
		PRINT("%d [%s], %p, %zu", fd, path, buf, count);
		break;
	}

	default:
		PRINT("??");
		break;
	}

	config->last_pid = tracee->pid;
	return 0;
}


#if !defined(MIN)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif


/**
 * Print the syscall and the values that where passed and will be returned
 * This function returns -errno if an error occured, otherwise 0.
 */
static int handle_sysexit_end(Tracee *tracee, Config *config)
{
	char path[PATH_MAX];
	int result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	word_t sysnum = get_sysnum(tracee, ORIGINAL);

	/* The pid changes iif the syscall was interupted */
	if (config->last_pid != tracee->pid) {
		printf(" ...\n\e[36m%5d\e[0m ... %s ...", tracee->pid, stringify_sysnum(sysnum));
	}

	/* Print the result of this syscall */
	switch (sysnum) {
	case PR_access:
	case PR_close:
	default:
		printf(" = \e[1;%dm%d\e[0m", result < 0 ? 31 : 32, result);
		break;
	}

	/* Print return data */
	switch (sysnum) {
	case PR_read: {
		word_t buf_addr = peek_reg(tracee, CURRENT, SYSARG_2);
		size_t count = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if (count == 0) {
			printf("\t%pd ''", (void *)buf_addr);
		} else {
	        count = MIN(count, 16);
			char buffer[count];
			read_data(tracee, buffer, buf_addr, count);
			printf("\t%p '%*s'", (void *)buf_addr, (int)count, buffer);
		}
		break;
    }
	}

	/* Print the terminating new line */
	printf("\n");
	config->last_pid = tracee->pid;
	return 0;
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
	    extension->config = talloc_zero(extension, Config);
	    if (extension->config == NULL)
	        return -1;

		extension->filtered_sysnums = filtered_sysnums;
		return 0;

	case INHERIT_PARENT: /* Inheritable for sub reconfiguration ...  */
		return 1;

	case INHERIT_CHILD: {
	    Extension *parent = (Extension *)data1;
	    Config *parent_config = talloc_get_type_abort(parent->config, Config);
	    talloc_reference(NULL, parent_config);
	    extension->config = parent_config;
	    return 0;
	}

	case SYSCALL_ENTER_END: {
	    Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);

	    return handle_sysenter_end(tracee, config);
	}

	case SYSCALL_EXIT_END: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);

		return handle_sysexit_end(tracee, config);
	}

	default:
		return 0;
	}
}
