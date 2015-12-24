/*
 * pfdmap.c: [poll]fd -> pid map for PSI polling
 * Copyright 2011 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */
#include <stdlib.h>
#include "pfdmap.h"

#define MAP_SIZE_INCREASE 16

int
add_to_pfd_map(struct pfd_map *map, uint16_t pid, int fd)
{
	int i;
	size_t size_pfds, size_pids;

	if (!map)
		return -1;

	for (i = 0; i < map->num_used; i++)
		if (map->pids[i] == pid)
			return 0;

	if (map->num_used + 1 > map->num_alloced) {
		map->num_alloced += MAP_SIZE_INCREASE;
		size_pfds = map->num_alloced * sizeof(map->pfds[0]);
		size_pids = map->num_alloced * sizeof(map->pids[0]);

		if (map->num_used == 0) {
			map->pfds = calloc(1, size_pfds);
			map->pids = calloc(1, size_pids);
		} else {
			map->pfds = realloc(map->pfds, size_pfds);
			map->pids = realloc(map->pids, size_pids);
		}
		if (!map->pfds || !map->pids) {
			map->num_alloced = 0;
			map->num_used = 0;
			free(map->pfds);
			free(map->pids);
			return -1;
		}
	}
	map->pfds[map->num_used].fd = fd;
	map->pfds[map->num_used].events = POLLIN;
	map->pfds[map->num_used].revents = 0;
	map->pids[map->num_used] = pid;
	map->num_used++;
	return 0;
}

int
remove_from_pfd_map(struct pfd_map *map, uint16_t pid)
{
	int i;

	if (!map)
		return -1;

	for (i = 0; i < map->num_used; i++)
		if (map->pids[i] == pid)
			break;
	if (i == map->num_used)
		return -2;

	map->num_used--;
	if (i != map->num_used) {
		map->pfds[i] = map->pfds[map->num_used];
		map->pids[i] = map->pids[map->num_used];
	}
	return 0;
}

void
free_pfd_map(struct pfd_map *map)
{
	if (!map || map->num_alloced == 0)
		return;
	free(map->pfds);
	free(map->pids);
	map->pfds = NULL;
	map->pids = NULL;
	map->num_alloced = 0;
}
