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

#ifndef PSTRACE_FLAGS_H_
#define PSTRACE_FLAGS_H_

#include <fcntl.h>
#include <sys/mman.h>

typedef struct {
  int value;
  const char *psz;
} value_string_t;


#define FLAG(c) { c, #c },
#define LAST_FLAG() { 0, NULL },
static const value_string_t access_flags[] = {
  FLAG(R_OK)
  FLAG(W_OK)
  FLAG(X_OK)
	LAST_FLAG()
};


static const value_string_t mmap_prots[] = {
	FLAG(PROT_NONE)
	FLAG(PROT_EXEC)
	FLAG(PROT_READ)
	FLAG(PROT_WRITE)
	LAST_FLAG()
};


static const value_string_t mmap_flags[] = {
	// TODO: what about MAP_ANON, MAP_EXECUTABLE, MAP_FILE and MAP_FIXED ?
	FLAG(MAP_SHARED)
	FLAG(MAP_PRIVATE)
	FLAG(MAP_32BIT)
	FLAG(MAP_ANONYMOUS)
	FLAG(MAP_DENYWRITE)
	FLAG(MAP_FIXED)
	FLAG(MAP_GROWSDOWN)
	FLAG(MAP_HUGETLB)
	FLAG(MAP_LOCKED)
	FLAG(MAP_NONBLOCK)
	FLAG(MAP_NORESERVE)
	FLAG(MAP_POPULATE)
	FLAG(MAP_STACK)
//	FLAG(MAP_UNINITIALIZED)
	LAST_FLAG()
};


static const value_string_t open_flags[] = {
	FLAG(O_RDONLY)
	FLAG(O_WRONLY)
	FLAG(O_RDWR)
	FLAG(O_APPEND)
	FLAG(O_ASYNC)
	FLAG(O_CLOEXEC)
	FLAG(O_CREAT)
	FLAG(O_DIRECT)
	FLAG(O_DIRECTORY)
	FLAG(O_EXCL)
//	FLAG(O_LARGEFILE) /* TODO: must define _LARGEFILE64_SOURCE ?
	FLAG(O_NOATIME)
	FLAG(O_NOCTTY)
	FLAG(O_NOFOLLOW)
	FLAG(O_NONBLOCK)
	FLAG(O_PATH)
	FLAG(O_SYNC)
	FLAG(O_TRUNC)
	LAST_FLAG()
};

#undef LAST_FLAG
#undef FLAG


typedef struct {
	const char *flag;
	const char *desc;
} errno_t;


#define DEF_ERRNO(flag, value, desc) [ value ] = {#flag, desc },
static const errno_t errno_flags[] = {
DEF_ERRNO(OK,		 0, "ok")
DEF_ERRNO(EPERM,	 1, "Operation not permitted")
DEF_ERRNO(ENOENT,	 2, "No such file or directory")
DEF_ERRNO(ESRCH,	 3, "No such process")
DEF_ERRNO(EINTR,	 4, "Interrupted system call")
DEF_ERRNO(EIO,		 5, "I/O error")
DEF_ERRNO(ENXIO,	 6, "No such device or address")
DEF_ERRNO(E2BIG,	 7, "Argument list too long")
DEF_ERRNO(ENOEXEC,	 8, "Exec format error")
DEF_ERRNO(EBADF, 	 9, "Bad file number")
DEF_ERRNO(ECHILD,	10, "No child processes")
DEF_ERRNO(EAGAIN,	11, "Try again")
DEF_ERRNO(ENOMEM,	12, "Out of memory")
DEF_ERRNO(EACCES,	13, "Permission denied")
DEF_ERRNO(EFAULT,	14, "Bad address")
DEF_ERRNO(ENOTBLK,	15, "Block device required")
DEF_ERRNO(EBUSY,	16, "Device or resource busy")
DEF_ERRNO(EEXIST,	17, "File exists")
DEF_ERRNO(EXDEV,	18, "Cross-device link")
DEF_ERRNO(ENODEV,	19, "No such device")
DEF_ERRNO(ENOTDIR,	20, "Not a directory")
DEF_ERRNO(EISDIR,	21, "Is a directory")
DEF_ERRNO(EINVAL,	22, "Invalid argument")
DEF_ERRNO(ENFILE,	23, "File table overflow")
DEF_ERRNO(EMFILE,	24, "Too many open files")
DEF_ERRNO(ENOTTY,	25, "Not a typewriter")
DEF_ERRNO(ETXTBSY,	26, "Text file busy")
DEF_ERRNO(EFBIG,	27, "File too large")
DEF_ERRNO(ENOSPC,	28, "No space left on device")
DEF_ERRNO(ESPIPE,	29, "Illegal seek")
DEF_ERRNO(EROFS,	30, "Read-only file system")
DEF_ERRNO(EMLINK,	31, "Too many links")
DEF_ERRNO(EPIPE,	32, "Broken pipe")
DEF_ERRNO(EDOM,		33, "Math argument out of domain of func")
DEF_ERRNO(ERANGE,	34, "Math result not representable")
};
#undef DEF_ERRNO

#endif /* PSTRACE_FLAGS_H_ */
