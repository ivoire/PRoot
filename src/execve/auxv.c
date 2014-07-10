/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2014 STMicroelectronics
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

#include <linux/auxvec.h>  /* AT_*,  */
#include <assert.h>        /* assert(3),  */
#include <errno.h>         /* E*,  */
#include <unistd.h>        /* write(3), close(3), */
#include <sys/types.h>     /* open(2), */
#include <sys/stat.h>      /* open(2), */
#include <fcntl.h>         /* open(2), */

#include "execve/auxv.h"
#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "path/binding.h"
#include "path/temp.h"
#include "tracee/abi.h"
#include "arch.h"

/**
 * Add the given vector [@type, @value] to @vectors.  This function
 * returns -errno if an error occurred, otherwise 0.
 */
int add_elf_aux_vector(ElfAuxVector **vectors, word_t type, word_t value)
{
	ElfAuxVector *tmp;
	size_t nb_vectors;

	assert(*vectors != NULL);

	nb_vectors = talloc_array_length(*vectors);

	/* Sanity checks.  */
	assert(nb_vectors > 0);
	assert((*vectors)[nb_vectors - 1].type == AT_NULL);

	tmp = talloc_realloc(talloc_parent(*vectors), *vectors, ElfAuxVector, nb_vectors + 1);
	if (tmp == NULL)
		return -ENOMEM;
	*vectors = tmp;

	/* Replace the sentinel with the new vector.  */
	(*vectors)[nb_vectors - 1].type  = type;
	(*vectors)[nb_vectors - 1].value = value;

	/* Restore the sentinel.  */
	(*vectors)[nb_vectors].type  = AT_NULL;
	(*vectors)[nb_vectors].value = 0;

	return 0;
}

/**
 * Find in @vectors the first occurrence of the vector @type.  This
 * function returns the found vector or NULL.
 */
ElfAuxVector *find_elf_aux_vector(ElfAuxVector *vectors, word_t type)
{
	int i;

	for (i = 0; vectors[i].type != AT_NULL; i++) {
		if (vectors[i].type == type)
			return &vectors[i];
	}

	return NULL;
}

/**
 * Get the address of the the ELF auxiliary vectors table for the
 * given @tracee.  This function returns 0 if an error occurred.
 */
word_t get_elf_aux_vectors_address(const Tracee *tracee)
{
	word_t address;
	word_t data;

	/* Sanity check: this works only in execve sysexit.  */
	assert(IS_IN_SYSEXIT2(tracee, PR_execve));

	/* Right after execve, the stack layout is:
	 *
	 *     argc, argv[0], ..., 0, envp[0], ..., 0, auxv[0].type, auxv[0].value, ..., 0, 0
	 */
	address = peek_reg(tracee, CURRENT, STACK_POINTER);

	/* Read: argc */
	data = peek_word(tracee, address);
	if (errno != 0)
		return 0;

	/* Skip: argc, argv, 0 */
	address += (1 + data + 1) * sizeof_word(tracee);

	/* Skip: envp, 0 */
	do {
		data = peek_word(tracee, address);
		if (errno != 0)
			return 0;
		address += sizeof_word(tracee);
	} while (data != 0);

	return address;
}

/**
 * Fetch ELF auxiliary vectors stored at the given @address in
 * @tracee's memory.  This function returns NULL if an error occurred,
 * otherwise it returns a pointer to the new vectors, in an ABI
 * independent form (the Talloc parent of this pointer is
 * @tracee->ctx).
 */
ElfAuxVector *fetch_elf_aux_vectors(const Tracee *tracee, word_t address)
{
	ElfAuxVector *vectors = NULL;
	ElfAuxVector vector;
	int status;

	/* It is assumed the sentinel always exists.  */
	vectors = talloc_array(tracee->ctx, ElfAuxVector, 1);
	if (vectors == NULL)
		return NULL;
	vectors[0].type  = AT_NULL;
	vectors[0].value = 0;

	while (1) {
		vector.type = peek_word(tracee, address);
		if (errno != 0)
			return NULL;
		address += sizeof_word(tracee);

		if (vector.type == AT_NULL)
			break; /* Already added.  */

		vector.value = peek_word(tracee, address);
		if (errno != 0)
			return NULL;
		address += sizeof_word(tracee);

		status = add_elf_aux_vector(&vectors, vector.type, vector.value);
		if (status < 0)
			return NULL;
	}

	return vectors;
}

/**
 * Push ELF auxiliary @vectors to the given @address in @tracee's
 * memory.  This function returns -errno if an error occurred,
 * otherwise 0.
 */
int push_elf_aux_vectors(const Tracee* tracee, ElfAuxVector *vectors, word_t address)
{
	size_t i;

	for (i = 0; vectors[i].type != AT_NULL; i++) {
		poke_word(tracee, address, vectors[i].type);
		if (errno != 0)
			return -errno;
		address += sizeof_word(tracee);

		poke_word(tracee, address, vectors[i].value);
		if (errno != 0)
			return -errno;
		address += sizeof_word(tracee);
	}

	return 0;
}

/**********************************************************************
 * Note: So far, the content of this file below is only required to
 * make GDB work correctly under PRoot.  However, it deserves to be
 * used unconditionally in execve sysexit.
 **********************************************************************/

/**
 * Remove @binding from all the lists it belongs to.
 *
 * Note: this is a Talloc destructor.
 */
static int remove_binding_from_all_lists2(Binding *binding)
{
	Tracee *tracee;

	tracee = talloc_parent(binding);
	if (tracee == NULL)
		return 0;  /* Not fatal.  */

	remove_binding_from_all_lists(tracee, binding);

	return 0;
}

/**
 * Fill @path with the content of @vectors, formatted according to
 * @ptracee's current ABI.
 */
static int fill_file_with_auxv(const Tracee *ptracee, const char *path,
			const ElfAuxVector *vectors)
{
	const ssize_t current_sizeof_word = sizeof_word(ptracee);
	ssize_t status;
	int fd = -1;
	int i;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;

	i = 0;
	do {
		status = write(fd, &vectors[i].type, current_sizeof_word);
		if (status < current_sizeof_word) {
			status = -1;
			goto end;
		}

		status = write(fd, &vectors[i].value, current_sizeof_word);
		if (status < current_sizeof_word) {
			status = -1;
			goto end;
		}
	} while (vectors[i++].type != AT_NULL);

	status = 0;
end:
	if (fd >= 0)
		(void) close(fd);

	return status;
}

/**
 * Fix @tracee's ELF auxiliary vectors in place, ie. in its memory.
 * This function returns NULL if an error occurred, otherwise it
 * returns a pointer to the new vectors, in an ABI independent form
 * (the Talloc parent of this pointer is @tracee->ctx).
 */
static ElfAuxVector *fix_elf_aux_vectors_in_mem(const Tracee *tracee)
{
	ElfAuxVector *vector_phdr;
	ElfAuxVector *vector_base;
	ElfAuxVector *vectors;
	word_t address;
	int status;

	address = get_elf_aux_vectors_address(tracee);
	if (address == 0)
		return NULL;

	vectors = fetch_elf_aux_vectors(tracee, address);
	if (vectors == NULL)
		return NULL;

	vector_phdr = find_elf_aux_vector(vectors, AT_PHDR);
	if (vector_phdr == NULL)
		return vectors;

	vector_base = find_elf_aux_vector(vectors, AT_BASE);
	if (vector_base == NULL)
		return vectors;

	/* Hum... This trick always works but this should be done more
	 * "scientifically".  */
	vector_base->value = vector_phdr->value & ~0xFFF;

	/* TODO: AT_PHDR and AT_ENTRY.  */

	status = push_elf_aux_vectors(tracee, vectors, address);
	if (status < 0)
		return NULL;

	return vectors;
}

/**
 * Fix ELF auxiliary vectors for the given @ptracee.  For information,
 * ELF auxiliary vectors have to be fixed because some of them are set
 * to unexpected values when the ELF interpreter is used as a loader
 * (AT_BASE for instance).  This function returns -1 if an error
 * occurred, otherwise 0.
 */
int fix_elf_aux_vectors(const Tracee *ptracee)
{
	const ElfAuxVector *vectors;
	const char *guest_path;
	const char *host_path;
	Binding *binding;
	int status;

	vectors = fix_elf_aux_vectors_in_mem(ptracee);
	if (vectors == NULL)
		return -1;

	guest_path = talloc_asprintf(ptracee->ctx, "/proc/%d/auxv", ptracee->pid);
	if (guest_path == NULL)
		return -1;

	host_path = create_temp_file(ptracee, "auxv");
	if (host_path == NULL)
		return -1;

	status = fill_file_with_auxv(ptracee, host_path, vectors);
	if (status < 0)
		return -1;

	/* This new binding will be removed once ptracee is
	 * destroyed.  */
	binding = insort_binding3(ptracee, ptracee, host_path, guest_path);
	if (binding == NULL)
		return -1;

	talloc_set_destructor(binding, remove_binding_from_all_lists2);

	/* This temporary file (host_path) will be removed once the
	 * binding is destroyed.  */
	talloc_reparent(ptracee->ctx, binding, host_path);

	return 0;
}
