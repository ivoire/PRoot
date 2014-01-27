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

#endif /* PSTRACE_FLAGS_H_ */
