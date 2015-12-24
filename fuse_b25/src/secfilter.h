/*
 * secfilter.h: convert text data in PSI sections from demuxN
 * Copyright 2011 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef _SECFILTER_H_
#define _SECFILTER_H_

#include <inttypes.h>

#include "stream.h"

enum sectype {
	SECTION_TYPE_NONE = 0,
	SECTION_TYPE_NIT,
	SECTION_TYPE_SDT,
	SECTION_TYPE_EIT,
	SECTION_TYPE_PES = 100,
};

struct secfilter_priv {
	int fd;
	struct options *fs_priv;
	iconv_t iconv_cd; // for text conversion
	enum sectype stype;

	int err; // last errno

	pthread_t filter_thread; //fetch and filter (and poll-notify) loop 
	pthread_mutex_t cancel_lock;
	struct fuse_pollhandle *ph; // for poll

	uint8_t inbuf[MAX_SECTION_SIZE]; // sizeof(inbuf) must be <= sizeof(outbuf)
	size_t inbuf_len;

	uint8_t outbuf[MAX_SECTION_SIZE * 4]; // ring buffer
	size_t outbuf_head;
	size_t outbuf_tail;

	uint8_t remaining_buf[MAX_SECTION_SIZE];
	size_t remaining_len;  // remaining data len not read by the previous read()

	pthread_mutex_t filter_lock;
	pthread_cond_t buf_cond;
};

uint16_t get_seclen(unsigned int idx, uint8_t *buf, size_t buf_size);

int secfilter_ioctl_hook(struct secfilter_priv *priv, int cmd, void *data);
int init_secfilter(struct secfilter_priv *priv);
void release_secfilter(struct secfilter_priv *priv);

#endif /* #ifndef _SECFILTER_H_ */


