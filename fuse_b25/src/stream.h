/*
 * stream.h: read & de-scramble data from DVR0
 * Copyright 2011 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef _STREAM_H_
#define _STREAM_H_

#include <stddef.h>
#include <inttypes.h>
#include <pthread.h>
#include <iconv.h>

#include "bcas.h"
#include "demulti2.h"
#include "pfdmap.h"

/* TS packet flags */
#define TS_F_TSEI 0x80
#define TS_F_PUSI 0x40
#define TS_CA_EVEN 0x80
#define TS_CA_ODD 0xc0
#define TS_CA_MASK 0xc0
#define TS_F_ADAP 0x20
#define TS_F_PAYLOAD 0x10
#define TS_CC_MASK 0x0f

#define CC_NONE 0xf0

/* PSI */
#define PID_PAT 0x0000
#define PID_CAT 0x0001
#define PID_NIT 0x0010
#define PID_SDT 0x0011
#define PID_EITH 0x0012
#define PID_NONE 0x1fff

#define TID_PAT 0x00
#define TID_CAT 0x01
#define TID_PMT 0x02
#define TID_ST 0x72
#define TID_ECM 0x82
#define TID_EMM 0x84

#define DESC_CA 0x09
#define DESC_STREAM_ID 0x52

/* ARIB TR-B14/15 */
#define ID_CAS_ARIB 0x0005
/* ARIB TR-B26 */
#define ID_CAS_ARIB_B 0x000A

#define CA_EMM_TYPE_A 0x01
#define CA_EMM_TYPE_B 0x02

#define VER_NONE 0x80

struct options {
	char *target; /* name of the target dvr device */
	char *card_name;
	int emm;  /* flag to process EMM */
	int conv; /* flag to convert NIT, SDT */
	int eit;  /* flag to convert EIT */
	int utc;  /* flag to adjust the time in EIT into UTC, */
	int cutoff; /* flag to discard the beginning of the stream */
			/* until the descrambling starts */

	char dvr_name[32];
	char dmx_name[32];
	struct bcas card;
};

struct stream_priv;

struct section {
	void *priv; // pointer to PMT, ECM, EMM...

	uint16_t pid;
	int fd; // file descriptor of the filtering demux device
	void (*cb_func)(struct stream_priv *, uint16_t pid);
	unsigned int refcount;

	/* section length */
	uint16_t len;

	/* buffer for de-packetized section data */
	uint8_t start_cc;
#define MAX_SECTION_SIZE (4096)
	uint8_t buf[MAX_SECTION_SIZE];
};


struct ecm {
	int ver;
	struct demulti2_key_info kinfo;
};

struct emm {
	int ver;
	uint8_t type;
};


struct ca {
	uint16_t cas_id;
	uint16_t pid;
	uint8_t  type;
};

struct pmt {
	int ver;
	int prog_id;
	int num_es;
#define PSI_MAX_ES 32
	struct pes {
		uint16_t es_pid;
		uint8_t es_type; // reserved
		uint8_t tag; // reserved
		struct ca es_ecm;
	} es[PSI_MAX_ES];

	struct ca prog_ecm;
};

struct pat {
	int ver;
	int ts_id;
	int num_prog;
#define PSI_MAX_PROG 8
	struct prog {
		uint16_t prog_id;
		uint16_t pmt_pid;
	} program[PSI_MAX_PROG];
};

struct cat {
	int ver;
	int num_cas;
#define PSI_MAX_CA 4
	struct ca emm[PSI_MAX_CA];
};

struct stream_priv {
	int fd; // file descriptor to the real DVR0 device
	struct options *fs_priv;

	size_t packet_size; // 188, 196?, 204, 212?, 220?

	struct section *sections[8192];

	struct pat pat;
	struct cat cat;

/* about 8kB buffer size */
#define MAX_FETCH_SIZE (188 * 43)
#define MAX_OUTBUF_SIZE (8 * 1024 * 1024)
/* MAX_SCAN_LEN must be <= MAX_FETCH_SIZE */
#define MAX_SCAN_LEN  (220 * 18)

	uint8_t inbuf[MAX_FETCH_SIZE]; // sizeof(inbuf) must be <= sizeof(outbuf)
	size_t inbuf_len;

	uint8_t outbuf[MAX_OUTBUF_SIZE]; // ring buffer
	size_t outbuf_head;
	size_t outbuf_tail;

	int err; // last errno

	int output_start; // whether descrambled output had started

	pthread_mutex_t buf_lock;
	pthread_cond_t buf_cond;
	pthread_t fetch_thread; //fetch (and poll-notify) loop 
	struct fuse_pollhandle *ph; // for poll
	pthread_mutex_t cancel_lock;

	iconv_t iconv_cd; // for text conversion

	// for the level 0 PSI's with fixed pid. PAT, CAT, NIT, SDT, EITH
	struct pfd_map fixed_pid_map;
	// level 0 PSI's whose pids are defined in PAT/CAT(level0).  PMT, EMM
	struct pfd_map pmt_emm_map;
	// level 2 PSI whose pid is defined in PMT(level1). ECM
	struct pfd_map ecm_map;
};

extern void push_outbuf(struct stream_priv *priv, uint8_t *buf, size_t len);
extern int init_stream(struct stream_priv *priv);
extern void release_stream(struct stream_priv *priv);

#endif // _STREAM_H_
