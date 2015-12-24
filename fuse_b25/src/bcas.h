/*
 * bcas.h: BCAS card I/O
 * Copyright 2009 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef _BCAS_H_
#define _BCAS_H_

#include <inttypes.h>
#include <pthread.h>
#include <winscard.h>

#include "demulti2.h"

#define BCAS_MAX_CARDID 8
#define BCAS_MAX_MSG_LEN 266


struct bcas {
	char *iccname;
	int errors; /* number of errors */

	uint16_t cas_id;
	enum {CARD_S_NG, CARD_S_OK} status;
	int num_id;
	uint8_t id[BCAS_MAX_CARDID][10]; 
	struct demulti2_param param;

	/* PC/SC card handles etc. used by bcas_card_*() */
	SCARDCONTEXT cxt;
	SCARDHANDLE hcard;

	/* command buffer to the BCAS PC card */
	/* (FIFO queue of length:1) */
	uint8_t cmdbuf[BCAS_MAX_MSG_LEN];
	/* length of the command  & the command processing status */
	/* if cmd_len > 0: command is issued, and waiting for the resp. */
	/* if cmd_len == 0: ready to accept new one. */
	volatile int cmd_len;
	/* callback func called when the response from the card is received */
	void  (*cmd_cb)(struct bcas *bcas, void *kinfo,
			uint8_t *rbuf, size_t rlen);
	void *cmd_arg;

	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int stop; /* tell the thread to stop */
};

extern int bcas_init(struct bcas *card);
extern void bcas_destroy(struct bcas *card);
extern void bcas_set_ecm(uint8_t *buf, int len,
			 struct demulti2_key_info *kinfo, struct bcas *bcas);
extern void bcas_set_emm(uint8_t *buf, struct bcas *bcas);

#endif // _BCAS_H_
