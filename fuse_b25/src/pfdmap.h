/*
 * pfdmap.h: [poll]fd -> pid map for PSI polling
 * Copyright 2011 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef _PFDMAP_H_
#define _PFDMAP_H_

#include <inttypes.h>
#include <poll.h>

struct pfd_map {
	unsigned int num_alloced;
	unsigned int num_used;
	struct pollfd *pfds;
	uint16_t *pids;
};

extern int add_to_pfd_map(struct pfd_map *map, uint16_t pid, int fd);
extern int remove_from_pfd_map(struct pfd_map *map, uint16_t pid);
extern void free_pfd_map(struct pfd_map *map);

#endif // _PFDMAP_H_
