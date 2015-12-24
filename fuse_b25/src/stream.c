/*
 * stream.c: read & de-scramble data from DVR0
 * Copyright 2011 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>

#include <poll.h>
#include <sys/ioctl.h>
#include <linux/dvb/dmx.h>

#define FUSE_USE_VERSION 28
#include <fuse.h>

#ifdef NO_SYSLOG
#define syslog(a, args...) fprintf(stderr, args...)
#endif

#include "stream.h"
#include "bcas.h"
#include "convert.h"

static void parse_pmt(struct stream_priv *priv, uint16_t pid);
static void parse_ecm(struct stream_priv *priv, uint16_t pid);
static void parse_emm(struct stream_priv *priv, uint16_t pid);

static struct section *get_section_for_pid(struct stream_priv *priv,
	uint16_t pid, void (*cb_func)(struct stream_priv *, uint16_t));
static void unref_section(struct stream_priv *priv, struct section *sec);

static int
ts_sync(uint8_t *buf, size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		if (buf[i] == 0x47)
			break;

	return (i == len) ? -1 : i;
}

#define NUM_OK_SYNC 5

/* returns the offset in priv->inbuf of the 1st TS packet */
static int
get_packet_size(struct stream_priv *priv)
{
	size_t size;
	int res;
	uint8_t *p;
	int i, j;

	p = priv->inbuf;
	for (size = 188; size <= 220; size += 8) {
		i = 0;
		while (i + NUM_OK_SYNC * 220 <= priv->inbuf_len) {
			res = ts_sync(&p[i], priv->inbuf_len - i);
			if (res < 0 ||
			    i + res + NUM_OK_SYNC * 220 > priv->inbuf_len)
				break;
			i += res;
			for (j = 0; j < NUM_OK_SYNC; j++)
				if (p[i + j * size] != 0x47)
					break;
			if (j == NUM_OK_SYNC) {
				priv->packet_size = size;
				syslog(LOG_DEBUG,
				       "detected TS packet size %lu bytes.\n",
				       size);
				return i;
			}
			i += j * size + 1;
		}
	}

	syslog(LOG_DEBUG, "failed to detect TS packet size.%m\n");
	priv->inbuf_len = 0;
	priv->packet_size = 0;
	return -1;
}

static void
unref_ecm(struct stream_priv *priv, struct pmt *pmt)
{
	int i;

	if (!priv || !pmt || pmt->ver == VER_NONE)
		return;

	if (pmt->prog_ecm.pid != PID_NONE)
		unref_section(priv, priv->sections[pmt->prog_ecm.pid]);
	for (i = 0; i < pmt->num_es; i++)
		if (pmt->es[i].es_ecm.pid != PID_NONE)
			unref_section(priv,
				priv->sections[pmt->es[i].es_ecm.pid]);
}

static void
parse_pat(struct stream_priv *priv, uint16_t pid)
{
	struct pat *pat = &priv->pat;
	struct pat oldpat;
	struct section *sec;
	int ver;
	int ts_id;
	int pnum;
	int i;
	uint8_t *p;
	uint16_t pmt_pid;

	sec = priv->sections[pid];

	if (sec->buf[0] != TID_PAT || sec->len < 12) {
		syslog(LOG_INFO, "received bad table[%#04hhx] for PAT.\n",
		       sec->buf[0]);
		return;
	}

	/* skip "next" table (which is illegal) */
	if (!(sec->buf[5] & 0x01))
		return;

	ts_id = (sec->buf[3] << 8) | sec->buf[4];
	ver = (int)(sec->buf[5] & 0x3e) >> 1;
	if (ver == pat->ver && ts_id == pat->ts_id)
		return;  // already parsed PAT

	pnum = (sec->len - 12) / 4;
	syslog(LOG_DEBUG, "new PAT for ts:%#06x, ver:%#04x, %d-progs.\n",
	       ts_id, ver, pnum);
	if (pnum > PSI_MAX_PROG)
		pnum = PSI_MAX_PROG;

	// backup the previous PAT, to manage refcount of the PMT sections
	memcpy(&oldpat, pat, sizeof(oldpat));
	pat->ver = ver;
	pat->ts_id = ts_id;
	pat->num_prog = 0;
	p = &sec->buf[8];
	for (i = 0; i < pnum; i++) {
		pat->program[pat->num_prog].prog_id = p[0] << 8 | p[1];
		pat->program[pat->num_prog].pmt_pid = (p[2] << 8 | p[3]) & 0x1fff;
		if (pat->program[pat->num_prog].prog_id != 0) {
			/* increment the refcount of the section.
			 * if it was used by the previous PAT, 
			 * the refcount will be 2, but decremented later.
			 */
			get_section_for_pid(priv,
				pat->program[pat->num_prog].pmt_pid, &parse_pmt);
			pat->num_prog++;
		}
		p += 4;
	}

	// remove the un-used old PMT-pids and/or their ECM-pids 
	if (oldpat.ver != VER_NONE) {
		for (i = 0; i < oldpat.num_prog; i++) {
			pmt_pid = oldpat.program[i].pmt_pid;
			unref_ecm(priv, priv->sections[pmt_pid]->priv);
			unref_section(priv, priv->sections[pmt_pid]);
		}
	}
	return;
}

static void
parse_pmt(struct stream_priv *priv, uint16_t pid)
{
	struct pmt *pmt;
	struct pmt oldpmt;
	struct section *sec;
	int ver;
	int prog_id;
	int i;
	uint8_t *p;
	int len;
	struct ca *ca;

	sec = priv->sections[pid];
	if (sec->buf[0] != TID_PMT) {
		if (sec->priv != NULL) {
			free(sec->priv);
			sec->priv = NULL;
		}
		goto bailout;
	}

	/* skip "next" table (which is illegal) */
	if (!(sec->buf[5] & 0x01))
		return;

	if (sec->priv == NULL) {
		sec->priv = calloc(1, sizeof(struct pmt));
		if (sec->priv == NULL) {
			syslog(LOG_INFO, "failed to alloc mem for PMT.\n");
			return;
		}
		pmt = sec->priv;
		pmt->ver = VER_NONE;
	}
	pmt = sec->priv;
	prog_id = (sec->buf[3] << 8) | sec->buf[4];
	ver = (sec->buf[5] & 0x3e) >> 1;

	if (ver == pmt->ver && prog_id == pmt->prog_id)
		return; // already processed PMT

	// backup the previous PMT, to manage refcount of the ECM sections
	memcpy(&oldpmt, pmt, sizeof(oldpmt));

	pmt->prog_id = prog_id;
	pmt->ver = ver;

	len = (sec->buf[10] & 0x0f) << 8 | sec->buf[11];
	if (sec->len < 12 + len)
		goto bailout;

	pmt->prog_ecm.pid = PID_NONE;
	p = &sec->buf[12];
	for (i=0; i + 2 < len; ) {
		if (i + p[1] + 2 > len)
			goto bailout;

		if (p[0] == DESC_CA && p[1] >= 4) {
			pmt->prog_ecm.cas_id = p[2] << 8 | p[3];
			pmt->prog_ecm.pid = (p[4] & 0x1f) << 8 | p[5];
			if (pmt->prog_ecm.cas_id != ID_CAS_ARIB &&
			    pmt->prog_ecm.pid != PID_NONE)
				syslog(LOG_INFO,
				      "found an invalid CAS-ID in PMT.\n");
			else if (pmt->prog_ecm.pid != PID_NONE)
				get_section_for_pid(priv, pmt->prog_ecm.pid,
					&parse_ecm);
			break;
		}

		i += p[1] + 2;
		p += p[1] + 2;
	}

	pmt->num_es = 0;
	p = &sec->buf[12] + len;
	while (p + 5 <= sec->buf + sec->len - 4) {
		pmt->es[pmt->num_es].es_type = p[0];
		pmt->es[pmt->num_es].es_pid = (p[1] & 0x1f)<<8 | p[2];

		pmt->es[pmt->num_es].tag = 0xff;
		pmt->es[pmt->num_es].es_ecm.pid = 0;

		len = (p[3] & 0x0f) <<8 | p[4];
		if (p + 5 + len > sec->buf + sec->len - 4)
			goto bailout;

		p += 5;
		for (i = 0; i + 2 < len;) {
			if (i + p[1] + 2 > len)
				goto bailout;

			if (p[0] == DESC_CA && p[1] >= 4) {
				ca = &pmt->es[pmt->num_es].es_ecm;
				ca->cas_id = p[2] << 8 | p[3];
				ca->pid =(p[4] & 0x1f) << 8 | p[5];
				if (ca->cas_id != ID_CAS_ARIB &&
				    ca->pid != PID_NONE)
					syslog(LOG_INFO,
					      "found an invalid CAS-ID in PMT.\n");
				else if (ca->pid != PID_NONE)
					get_section_for_pid(priv, ca->pid,
						&parse_ecm);
			} else if (p[0] == DESC_STREAM_ID && p[1] >= 1)
				pmt->es[pmt->num_es].tag = p[2];

			i += p[1] + 2;
			p += p[1] + 2;
		}
		if (i != len)
			goto bailout;
		pmt->num_es++;
		if (pmt->num_es == PSI_MAX_ES)
			break;
	}

	unref_ecm(priv, &oldpmt);
	syslog(LOG_DEBUG, "new PMT for prog:%#06x, ver:%#04x, %d-pes's.\n",
	       prog_id, ver, pmt->num_es);

	return;

bailout:
	syslog(LOG_INFO, "received bad table for PMT.\n");
	return;
}

static void
parse_ecm(struct stream_priv *priv, uint16_t pid)
{
	struct ecm *ecm;
	struct section *sec;
	int ver;

	sec = priv->sections[pid];
	if (sec->buf[0] != TID_ECM) {
		syslog(LOG_INFO, "received broken header for ECM.\n");
		goto bailout;
	}

	if (sec->priv == NULL) {
		sec->priv = calloc(1, sizeof(struct ecm));
		if (sec->priv == NULL) {
			syslog(LOG_INFO, "failed to alloc mem for ECM.\n");
			return;
		}
		ecm = sec->priv;
		ecm->ver = VER_NONE;
	}

	/* ECM section must be contained in one TS packet, */
	/*  and min payload len >= 30 */
	if (sec->len > 188 || sec->len < 30 + 12)
		goto bailout;

	ecm = sec->priv;
	ecm->kinfo.parent_sec = sec;

	/* cur/next flag should be always 1, */
	/* but processing the "next" ECM in advance is OK */
	ver = (sec->buf[5] & 0x3e) >> 1;
	if (ver == ecm->ver)
		return; // already processed PMT

	ecm->ver = ver;
	syslog(LOG_DEBUG, "new ECM. ver:[0x%02x].\n", ver);

	bcas_set_ecm(sec->buf + 8, sec->len - 12, &ecm->kinfo, &priv->fs_priv->card);
	return;

bailout:
	syslog(LOG_INFO, "received bad table for ECM.\n");
	return;
}

static void
parse_cat(struct stream_priv *priv, uint16_t pid)
{
	struct cat *cat = &priv->cat;
	struct cat oldcat;
	struct section *sec;
	int ver;
	uint8_t *p;
	struct ca *ca;
	int i;
	uint16_t emm_pid;

	sec = priv->sections[pid];
	if (sec->buf[0] != TID_CAT || sec->len < 12) {
		syslog(LOG_INFO, "received bad table[%#04hhx] for CAT.\n",
		       sec->buf[0]);
		return;
	}

	/* skip "next" table (which is illegal) */
	if (!(sec->buf[5] & 0x01))
		return;

	ver = (sec->buf[5] & 0x3e) >> 1;
	if (ver == cat->ver)
		return;  // already parsed CAT

	memcpy(&oldcat, cat, sizeof(oldcat));
	cat->ver = ver;
	cat->num_cas = 0;
	p = &sec->buf[8];
	while (p + 2 <= sec->buf + sec->len - 4) {
		if (p + p[1] + 2 > sec->buf + sec->len - 4)
			goto bailout;

		if (p[0] == DESC_CA && p[1] >= 5) {
			ca = &cat->emm[cat->num_cas];
			ca->cas_id = p[2] << 8 | p[3];
			ca->pid =(p[4] & 0x1f) << 8 | p[5];
			ca->type = p[6];

			if (ca->cas_id == ID_CAS_ARIB && ca->pid != PID_NONE)
				get_section_for_pid(priv, ca->pid, &parse_emm);
			cat->num_cas++;
			if (cat->num_cas >= PSI_MAX_CA)
				break;
		}
		p += p[1] + 2;
	}

	// remove the un-used old EMM-pids
	if (oldcat.ver != VER_NONE) {
		for (i = 0; i < oldcat.num_cas; i++) {
			emm_pid = oldcat.emm[i].pid;
			if (emm_pid < PID_NONE)
				unref_section(priv, priv->sections[emm_pid]);
		}
	}
	syslog(LOG_DEBUG, "new CAT, ver:%#04x, %d-CAs.\n", ver, cat->num_cas);
	return;

bailout:
	syslog(LOG_INFO, "received bad table for CAT.\n");
	return;
}


static void
parse_emm(struct stream_priv *priv, uint16_t pid)
{
	struct emm *emm;
	struct section *sec;
	struct bcas *card = &priv->fs_priv->card;
	int ver;

	int i;
	uint8_t *p;
	int res;

	sec = priv->sections[pid];
	if (sec->buf[0] != TID_EMM) {
		if (sec->priv != NULL) {
			free(sec->priv);
			sec->priv = NULL;
		}
		goto bailout;
	}

	if (sec->priv == NULL) {
		sec->priv = calloc(1, sizeof(struct emm));
		if (sec->priv == NULL) {
			syslog(LOG_INFO, "failed to alloc mem for EMM.\n");
			return;
		}
		emm = sec->priv;
		emm->ver = VER_NONE;
	} else
		emm = sec->priv;

	/* skip "next" table (which is illegal) */
	if (!(sec->buf[5] & 0x01))
		return;

	ver = (sec->buf[5] & 0x3e) >> 1;
	if (ver == emm->ver)
		return;  // already parsed EMM

	emm->ver = ver;
	if (emm->type == 0) {
		/* emm type not set yet */
		for (i = 0; i < priv->cat.num_cas; i++)
			if (priv->cat.emm[i].pid == pid) {
				emm->type = priv->cat.emm[i].type;
				break;
			}

		if (emm->type == 0)
			goto bailout;
	}

	p = &sec->buf[8];
	if (p + p[6] + 7 >= sec->buf + sec->len - 4)
		goto bailout;

	switch (emm->type) {
	case CA_EMM_TYPE_A:
		/* TypeA: multi EMM/sec, no GroupID */
		/* check the 1st EMM (minID) */
		res = memcmp(&card->id[0][2], p, 6);
		if (res == 0)
			goto found;
		if (res < 0)
			return; // not mine

		/* check the second EMM (maxID) */
		p += p[6] + 7;
		if (p + p[6] + 7 >= sec->buf + sec->len - 4)
			goto bailout;

		res = memcmp(&card->id[0][2], p, 6);
		if (res == 0)
			goto found;
		if (res > 0)
			return;

		p += p[6] + 7;
		while (p + p[6] + 7 <= sec->buf + sec->len - 4) {
			res = memcmp(&card->id[0][2], p, 6);
			if (res == 0)
				goto found;
			if (res < 0)
				break;
			p += p[6] + 7;
		}
		return;
		break;

	case CA_EMM_TYPE_B:
		/* TypeB: 1 EMM / sec, GroupID possible */
		for (i=0; i < card->num_id; i++) {
			res = memcmp(&card->id[i][2], p, 6);
			if (res == 0)
				goto found;
		}
		return;
		break;

	default:
		goto bailout;
	}

found:
	syslog(LOG_INFO, "received new EMM.\n");
	bcas_set_emm(p, card);
	return;

bailout:
	syslog(LOG_INFO, "received bad table for EMM.\n");
	return;
}

static struct pfd_map *
get_pfd_map(struct stream_priv *priv,
	void (*cb_func)(struct stream_priv *, uint16_t))
{
	if (cb_func == &parse_ecm)
		return &priv->ecm_map;
	else if (cb_func == &parse_pmt || cb_func == &parse_emm)
		return &priv->pmt_emm_map;
	else
		return &priv->fixed_pid_map;
}

static void
cleanup_section(struct stream_priv *priv, struct section *sec)
{
	if (!priv || !sec || sec->pid > PID_NONE)
		return;

	if (remove_from_pfd_map(get_pfd_map(priv, sec->cb_func), sec->pid)) {
		syslog(LOG_INFO,
			"failed to remove the section(pid:%#06hx).\n",
			sec->pid);
	}
	if (sec->priv != NULL)
		free(sec->priv);
	ioctl(sec->fd, DMX_STOP);
	close(sec->fd);
	priv->sections[sec->pid] = NULL;
	free(sec);
}

static void
unref_section(struct stream_priv *priv, struct section *sec)
{
	if (!priv || !sec || sec->pid < 0x20 || sec->pid > PID_NONE)
		return;

	if (sec->refcount > 0)
		sec->refcount--;

	if (sec->refcount)
		return;

	syslog(LOG_DEBUG, "removed the section for pid:[%#06hx].\n", sec->pid);
	cleanup_section(priv, sec);
}

static struct section *
get_section_for_pid(struct stream_priv *priv, uint16_t pid,
	void (*cb_func)(struct stream_priv *, uint16_t))
{
	struct section *sec;
	struct dmx_sct_filter_params secfilter;
	int err;

	if (priv == NULL || pid > 0x1fff)
		return NULL;

	sec = priv->sections[pid];
	if (sec && sec->cb_func != cb_func) {
		syslog(LOG_INFO, "PID:%#06hx is reused by another"
			" type of section", pid);
		cleanup_section(priv, sec);
		sec = NULL;
	}
	if (sec == NULL) {
		sec = calloc(1, sizeof(struct section));
		if (sec == NULL)
			return NULL;

		sec->pid = pid;
		sec->cb_func = cb_func;
		sec->fd = open(priv->dmx_name, O_RDONLY | O_NONBLOCK);
		if (sec->fd < 0) {
			err = errno;
			syslog(LOG_INFO, "failed to open the demux device:%s\n",
				priv->dmx_name);
			free(sec);
			errno = err;
			return NULL;
		}
		if (add_to_pfd_map(get_pfd_map(priv, cb_func), pid, sec->fd)) {
			syslog(LOG_INFO, "failed to add the pollfd for pid:"
				"%#06hx.\n", pid);
			close(sec->fd);
			free(sec);
			errno = ENOMEM;
			return NULL;
		}
		memset(&secfilter, 0, sizeof(secfilter));
		secfilter.pid = pid;
		secfilter.flags = DMX_IMMEDIATE_START;
		if (ioctl(sec->fd, DMX_SET_FILTER, &secfilter) < 0) {
			err = errno;
			syslog(LOG_INFO, "failed to set the filter for pid:"
				"%#06hx to the demux device:%s\n",
				pid, priv->dmx_name);
			if (remove_from_pfd_map(get_pfd_map(priv, cb_func), pid))
				syslog(LOG_INFO, "failed to remove the poll fd"
					" for pid:%#06hx.\n", pid);
			close(sec->fd);
			free(sec);
			errno = err;
			return NULL;
		}
		priv->sections[pid] = sec;
		syslog(LOG_DEBUG, "created new section for pid:[%#06hx].\n", pid);
	}
	sec->refcount++;
	return sec;
}


static void
descramble(struct stream_priv *priv, uint8_t *buf,
	   struct ca *prog_ecm, struct ca *es_ecm)
{
	uint8_t *p;
	int len;
	struct ca *ca;
	struct ecm *ecm;
	struct bcas *card = &priv->fs_priv->card;

	p = buf + 4;
	if (buf[3] & TS_F_ADAP)
		p += *p + 1;

	len = 188 - (p - buf);
	if (len <= 0)
		return;

	/* get ecm_pid */

	if (es_ecm->pid == 0)
		ca = prog_ecm;
	else if (es_ecm->pid == PID_NONE)
		goto noscrambled;
	else
		ca = es_ecm;

	if (ca->pid == 0 || ca->pid == PID_NONE)
		goto noscrambled;

	if (ca->cas_id != card->cas_id) {
		syslog(LOG_INFO, "CAS:[0x%04hx] of pid:[0x%04hx] != "
			"CAS:[0x%04hx] of the card.\n",	ca->cas_id,
			(buf[1] & 0x1f) << 8 | buf[2], card->cas_id);
		return;
	}
	if (priv->sections[ca->pid] == NULL)
		goto notready;
	ecm = priv->sections[ca->pid]->priv;
	if (ecm == NULL)
		goto notready;
	if (ecm->ver == VER_NONE)
		goto notready;

	pthread_mutex_lock(&card->lock);
	if (card->status != CARD_S_OK) {
		pthread_mutex_unlock(&card->lock);
		goto notready;
	}
	if (ecm->kinfo.status == CMD_S_VOID ||
	    ecm->kinfo.status == CMD_S_QUERYING ||
	    ecm->kinfo.status == CMD_S_FAILED) {
		pthread_mutex_unlock(&card->lock);
		goto notready;
	}
	demulti2(p, len, &card->param,
		ecm->kinfo.wrk[(buf[3] & TS_CA_MASK) == TS_CA_EVEN]);
	pthread_mutex_unlock(&card->lock);

	if (!priv->output_start)
		syslog(LOG_DEBUG, "descramle started.\n");
	priv->output_start = 1;
	buf[3] &= ~TS_CA_MASK;
	return;

noscrambled:
	syslog(LOG_DEBUG, "packet CA flag is set but PMT denies.\n");
	return;

notready:
//	syslog(LOG_DEBUG, " BCAS is not yet ready for de-scrambling.\n");
	return;
}


static inline void
advance(size_t *a, size_t size, size_t len)
{
	*a += len;
	if (*a >= size)
		*a -= size;
}

/* copy one TS packet(188B) to the output ring-buffer */
void
push_outbuf(struct stream_priv *priv, uint8_t *buf, size_t len)
{
	int l;

	if (!priv->output_start && priv->fs_priv->cutoff) {
		//syslog(LOG_DEBUG, "not yet prepared to outputuf, discarding data.\n");
		return;
	}

	if (priv->outbuf_head > priv->outbuf_tail) {
		l = sizeof(priv->outbuf) - priv->outbuf_tail;
		if (l >= len)
			memcpy(priv->outbuf + priv->outbuf_tail, buf, len);
		else {
			memcpy(priv->outbuf + priv->outbuf_tail, buf, l);
			memcpy(priv->outbuf, buf + l, len - l);
		}
		if (priv->outbuf_head - priv->outbuf_tail <= len) {
			syslog(LOG_DEBUG, "outbuf overflowed.\n");
			advance(&priv->outbuf_head, sizeof(priv->outbuf), 188);
		}
		advance(&priv->outbuf_tail, sizeof(priv->outbuf), len);
	} else {
		l = sizeof(priv->outbuf) - priv->outbuf_tail;
		if (l >= len)
			memcpy(priv->outbuf + priv->outbuf_tail, buf, len);
		else {
			memcpy(priv->outbuf + priv->outbuf_tail, buf, l);
			memcpy(priv->outbuf, buf + l, len - l);
			if (len -l >= priv->outbuf_head) {
				syslog(LOG_DEBUG, "outbuf overflowed.\n");
				advance(&priv->outbuf_head,
					sizeof(priv->outbuf), 188);
			}
		}
		advance(&priv->outbuf_tail, sizeof(priv->outbuf), len);
	}
}


/* parse  one TS packet */
/* and put the output into priv->outbuf */
static void
process_packet(struct stream_priv *priv, uint8_t *buf)
{
	uint16_t pid;
	int i, j;
	struct section *sec;
	struct pmt *pmt;
	struct bcas *card = &priv->fs_priv->card;

	if (buf[1] & TS_F_TSEI)
		return;

	pid = (buf[1] & 0x1f) << 8 | buf[2];
	if (pid == PID_NONE)
		return;

#if HAVE_ICONV_H
	/* if the packet is part of the PSI which is set to be converted,
	 * the same data is read from the section filter descriptor as well.
	 * thus, let its section callback func output the converted data,
	 *  and don't output here.
	 */
	if (priv->fs_priv->conv && pid == PID_NIT)
		return;
	if (priv->fs_priv->conv && pid == PID_SDT)
		return;
	if ((priv->fs_priv->eit || priv->fs_priv->utc) && pid == PID_EITH)
		return;
#endif

	/* descramble the packet (if the necessary PSI's are available) */
	if (pid >= 0x002a && (buf[3] & TS_CA_MASK) &&
	    card->status == CARD_S_OK) {
		if (pid == PID_NONE)
			goto done;

		/* check non-fixed-pid PSI: PMT,ECM,EMM */
		if (priv->cat.ver != VER_NONE) {
			for (i = 0; i< priv->cat.num_cas; i++)
				if (priv->cat.emm[i].pid == pid)
					goto done;
		}

		if (priv->pat.ver == VER_NONE)
			goto done;

		for (i = 0; i < priv->pat.num_prog; i++) {
			if (priv->pat.program[i].prog_id == 0)
				continue;
			if (priv->pat.program[i].pmt_pid == pid)
				goto done;

			sec = priv->sections[priv->pat.program[i].pmt_pid];
			if (sec == NULL)
				continue;
			if (sec->priv == NULL)
				continue;
			pmt = sec->priv;
			if (pmt->ver == VER_NONE)
				continue;

			if (pmt->prog_ecm.pid == pid)
				goto done;

			for (j = 0; j < pmt->num_es; j++) {
				if (pmt->es[j].es_pid == pid) {
					descramble(priv, buf, &pmt->prog_ecm,
						    &pmt->es[j].es_ecm);
					goto done;
				}
				if (pmt->es[j].es_ecm.pid == pid)
					goto done;
			}
		}
	}

done:
	if (buf[3] & TS_CA_MASK) {
#if REPLACE_WITH_NULL
		buf[1] |= 0x1f;
		buf[2] = 0xff;
		buf[3] &= ~TS_CA_MASK;
#else
		return;
#endif
	}
	push_outbuf(priv, buf, 188);
	return;
}

static int
setup_fixed_pid_sections(struct stream_priv *priv)
{
	if (!get_section_for_pid(priv, PID_PAT, &parse_pat))
		return -1;

	if (priv->fs_priv->emm) {
		if (!get_section_for_pid(priv, PID_CAT, &parse_cat))
			return -1;
	}

	if (priv->fs_priv->conv) {
		if (!get_section_for_pid(priv, PID_NIT, &convert_nit))
			return -1;

		if (!get_section_for_pid(priv, PID_SDT, &convert_sdt))
			return -1;
	}

	if (priv->fs_priv->eit || priv->fs_priv->utc) {
		if (!get_section_for_pid(priv, PID_EITH, &convert_eith))
			return -1;
	}
	return 0;
}

static int
do_read_section(struct stream_priv *priv, struct pfd_map *map, int timeout)
{
	int i;
	int res;
	uint16_t pid;
	int err = 0;
	struct section *sec;
	int seclen;

	if (map->num_used == 0)
		return 0;

	res = poll(map->pfds, map->num_used, timeout);
	if (res < 0) {
		err = errno;
		goto failed;
	}

	if (res == 0)
		return 0;

	for (i = 0; i < map->num_used; i++) {
		if (map->pfds[i].revents == POLLIN) {
			pid = map->pids[i];
			sec = priv->sections[pid];
			if (!sec) {
				err = EINVAL;
				syslog(LOG_INFO, "poll found a invalid"
					" section for pid:%#06hx", pid);
				goto failed;
			}
			res = read(map->pfds[i].fd, sec->buf, sizeof(sec->buf));
			seclen = (sec->buf[1] & 0x0f) << 8 | sec->buf[2];
			if (res < seclen + 3) {
				err = errno;
				syslog(LOG_INFO, "failed to read the"
					" section for pid:%#06hx", pid);
				goto failed;
			}
			sec->len = res;
			if (sec->cb_func)
				sec->cb_func(priv, pid);
		} else if (map->pfds[i].revents != 0) {
			err = EIO;
			syslog(LOG_INFO, "poll received an error on the fd"
				" for pid:%#06hx", map->pids[i]);
			goto failed;
		}
	}

	return 0;

failed:
	err = errno;
	syslog(LOG_INFO, "failed to poll. errno:%d.\n", err);
	return err;
}

static void
fetch_loop_cleanup(void *data)
{
	struct stream_priv *priv = (struct stream_priv *)data;

	pthread_mutex_unlock(&priv->buf_lock);
	pthread_mutex_unlock(&priv->cancel_lock);
}

static void *
fetch_loop(void *data)
{
	struct stream_priv *priv = (struct stream_priv *)data;
	int res;
	uint8_t *p;
	int min_read;
	int len;
	int timeout;
	int err = 0;
	struct pollfd pfd;

	pthread_cleanup_push(fetch_loop_cleanup, data);

	if (setup_fixed_pid_sections(priv) < 0) {
		syslog(LOG_INFO, "failed to setup pollfd's for PAT etc.\n");
		goto failed;
	}

	pfd.fd = priv->fd;
	pfd.events = POLLIN;
	min_read = MAX_SCAN_LEN;
	while (1) {
		/* check for data availability of each fd's */
		timeout = (priv->pat.ver != VER_NONE) ? 0 : -1;
		err = do_read_section(priv, &priv->fixed_pid_map, timeout);
		if (err)
			goto failed;

		err = do_read_section(priv, &priv->pmt_emm_map, 0);
		if (err)
			goto failed;

		res = do_read_section(priv, &priv->ecm_map, 0);
		if (err)
			goto failed;

		/* read from dvr0 dev */
		p = priv->inbuf + priv->inbuf_len;
		res = poll(&pfd, 1, 10);
		while (res > 0 && priv->inbuf_len < min_read) {
			res = (int)read(priv->fd, p,
					sizeof(priv->inbuf) - priv->inbuf_len);
			if (res == 0 || (res <= 0 && errno != EAGAIN)) {
				err = errno;
				syslog(LOG_INFO, "failed to read. ret:%d err:%d",
					res, err);
				goto failed;
			} else if (res < 0) {
				// EAGAIN
				res = 0;
				break;
			}
			p += res;
			priv->inbuf_len += res;
			res = poll(&pfd, 1, 0); // redundant?
		};

		if (res < 0) {
			err = errno;
			syslog(LOG_INFO, "failed to poll on dvr.\n");
			goto failed;
		} else if (priv->inbuf_len < min_read) {
			// res==0. read all data but not enough
			continue;
		}

		p = priv->inbuf;
		len = priv->inbuf_len;

		if (priv->packet_size == 0) {
			res = get_packet_size(priv);
			if (res < 0) {
				err = EIO;
				goto failed;
			} else {
				min_read = priv->packet_size;
				p += res;
				len -= res;
			}
		}

		sched_yield();

		/* to prohibit the cancel of this thread by release_stream() */
		pthread_mutex_lock(&priv->cancel_lock);
		/*
		 * only push_outbuf() in process_packet() requires the lock,
		 * but push_outbuf() is called every packet,
		 * so lock here at the fetch block level.
		 */
		pthread_mutex_lock(&priv->buf_lock);

		while (len >= priv->packet_size) {
			if (*p != 0x47) {
				syslog(LOG_DEBUG, "sync lost.\n");
				res = ts_sync(p, len);
				if (res < 0) {
					syslog(LOG_INFO, "failed to sync.\n");
					priv->inbuf_len = 0;
					priv->packet_size = 0;
					min_read = MAX_SCAN_LEN;
					len = 0;
					break;
				}
				p += res;
				len -= res;
				continue;
			}
			process_packet(priv, p);
			p += priv->packet_size;
			len -= priv->packet_size;
		}

		if (priv->outbuf_head != priv->outbuf_tail) {
			if (priv->ph != NULL) {
				fuse_notify_poll(priv->ph);
				fuse_pollhandle_destroy(priv->ph);
				priv->ph = NULL;
			}
			pthread_cond_signal(&priv->buf_cond);
		}
		pthread_mutex_unlock(&priv->buf_lock);
		pthread_mutex_unlock(&priv->cancel_lock);

		/* move the remainder fragment to the head */
		if (len > 0)
			memcpy(priv->inbuf, p, len);
		priv->inbuf_len = len;
	}

failed:
	pthread_mutex_lock(&priv->buf_lock);
	if (err == 0)
		err = EIO;
	priv->err = err;
	pthread_cond_signal(&priv->buf_cond);
	pthread_mutex_unlock(&priv->buf_lock);
	syslog(LOG_INFO, " fuse_b25 fetch loop exited.\n");
	pthread_cleanup_pop(0);
	return NULL;
}



/* exported functions */

int
init_stream(struct stream_priv *priv)
{
	priv->pat.ver = VER_NONE;
	priv->cat.ver = VER_NONE;

	if (snprintf(priv->dmx_name, sizeof(priv->dmx_name),
		"%s/demux%u", priv->fs_priv->target_dir, priv->dvr_no) < 0) {
		syslog(LOG_INFO, "failed to create demuxer device name.\n");
		return -ENXIO;
	}

	pthread_mutex_init(&priv->cancel_lock, NULL);
	pthread_mutex_init(&priv->buf_lock, NULL);
	pthread_cond_init(&priv->buf_cond, NULL);

	if (priv->fs_priv->conv || priv->fs_priv->eit) {
		priv->iconv_cd = iconv_open("UTF-16BE//TRANSLIT", "EUC-JISX0213");
		if (priv->iconv_cd == (iconv_t)-1) {
			syslog(LOG_INFO,
			       "text conv. disabled as iconv_open() failed:%m\n");
			priv->fs_priv->conv = 0;
			priv->fs_priv->eit = 0;
		}
	}

	if (pthread_create(&priv->fetch_thread, NULL, fetch_loop, priv))
		return -errno;
	return 0;
}


void
release_stream(struct stream_priv *priv)
{
	int i;
	struct bcas *card = &priv->fs_priv->card;

	pthread_mutex_lock(&priv->cancel_lock);
	pthread_cancel(priv->fetch_thread);
	pthread_mutex_unlock(&priv->cancel_lock);

	pthread_mutex_lock (&card->lock);
	/* wait for the last cmd to finish */
	while (card->status == CARD_S_OK && !card->sleeping) {
		pthread_mutex_unlock(&card->lock);
		usleep(1000 * 100);
		pthread_mutex_lock(&card->lock);
	}

#if 0
	card->cmd_len = BCAS_RESET_REQUEST; // tells BCAS to reset
	pthread_cond_broadcast(&card->cond);
#endif
	pthread_mutex_unlock(&card->lock);

	pthread_join(priv->fetch_thread, NULL);

	if (priv->fs_priv->conv && priv->iconv_cd != (iconv_t)-1)
		iconv_close(priv->iconv_cd);

	for (i = 0; i < 8192; i++)
		if (priv->sections[i] != NULL)
			cleanup_section(priv, priv->sections[i]);

	free_pfd_map(&priv->fixed_pid_map);
	free_pfd_map(&priv->pmt_emm_map);
	free_pfd_map(&priv->ecm_map);
}
