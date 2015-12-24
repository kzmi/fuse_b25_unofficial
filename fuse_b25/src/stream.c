/*
 * stream.c: read & de-scramble data from DVR0
 * Copyright 2009 0p1pp1
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

#define FUSE_USE_VERSION 28
#include <fuse.h>

#ifdef NO_SYSLOG
#define syslog(a, args...) fprintf(stderr, args...)
#endif

#include "stream.h"
#include "bcas.h"

/* text conversion related funcs (in convert.c) */
extern void convert_nit(struct stream_priv *priv, uint16_t pid);
extern void convert_sdt(struct stream_priv *priv, uint16_t pid);
extern void convert_eith(struct stream_priv *priv, uint16_t pid);

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
				       "detected TS packet size %u bytes.\n",
				       size);
				return i;
			}
			i += j * size + 1;
		}
	}

failed:
	syslog(LOG_DEBUG, "failed to detect TS packet size.%m\n");
	priv->inbuf_len = 0;
	priv->packet_size = 0;
	return -1;
}


static void
parse_pat(struct stream_priv *priv, uint16_t pid)
{
	struct pat *pat = &priv->pat;
	struct section *sec;
	int ver;
	int ts_id;
	int pnum;
	int i;
	uint8_t *p;

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

	pat->ver = ver;
	pat->ts_id = ts_id;
	pat->num_prog = pnum;
	p = &sec->buf[8];
	for (i = 0; i < pnum; i++) {
		pat->program[i].prog_id = p[0] << 8 | p[1];
		pat->program[i].pmt_pid = (p[2] << 8 | p[3]) & 0x1fff;
		p += 4;
	}
	return;
}

static void
parse_pmt(struct stream_priv *priv, uint16_t pid)
{
	struct pmt *pmt;
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

	syslog(LOG_DEBUG, "new PMT for prog:%#06x, ver:%#04x, %d-pes's.\n",
	       prog_id, ver, pmt->num_es);


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

	int i;
	uint8_t *p;
	int len;
	struct ca *ca;

	sec = priv->sections[pid];
	if (sec->buf[0] != TID_ECM) {
		if (sec->priv != NULL) {
			free(sec->priv);
			sec->priv = NULL;
		}
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
	struct section *sec;
	int ver;
	uint8_t *p;
	struct ca *ca;

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

			cat->num_cas++;
			if (cat->num_cas >= PSI_MAX_CA)
				break;
		}
		p += p[1] + 2;
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
	}

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


/*
 * build up a PSI section 
 *  call section_cb() on (every) section complete, 
 */
static void
push_section(struct stream_priv *priv, uint8_t *buf,
	     void (*section_cb)(struct stream_priv *, uint16_t))
{
	struct section *sec;
	uint16_t pid;
	uint8_t cc;
	uint8_t *p;
	int len;

	pid = (buf[1] & 0x1f) << 8 | buf[2];
	cc = buf[3] & TS_CC_MASK;

	sec = priv->sections[pid];
	if (sec == NULL) {
		sec = calloc(1, sizeof(struct section));
		if (sec == NULL) {
			syslog(LOG_NOTICE, "failed to alloc section buffer.\n");
			return;
		}
		priv->sections[pid] = sec;
		sec->last_cc = CC_NONE;
		syslog(LOG_DEBUG, "created new section for pid:[%#06hx].\n", pid);
	}

	p = buf + 4;
	if (buf[3] & TS_F_ADAP)
		p += *p + 1;
	len = 188 - (p - buf);
	if (len < 3 || !(buf[3] & TS_F_PAYLOAD)) // too short/no payload
		return;

	if (buf[1] & TS_F_PUSI)
		len = *p++;

	// fill  the previous section
	if (cc == ((sec->last_cc + 1) & 0x0f) && len > 0 && sec->len > 0) {
		sec->last_cc = cc;
		if (sec->len - sec->buflen <= len) {
			memcpy(&sec->buf[sec->buflen], p, sec->len - sec->buflen);
			sec->buflen = sec->len;
			section_cb(priv, pid);
			sec->last_cc = CC_NONE;
		} else {
			memcpy(&sec->buf[sec->buflen], p, len);
			sec->buflen += len;
		}
	}
	p += len;

	while ((buf[1] & TS_F_PUSI) && p + 3 <= buf + 188) {
		if (*p == 0xff || *p == TID_ST)
			break;
		/* new section starts */

		if (sec->buf[0] != p[0] && sec->priv != NULL) {
			if (pid != PID_EITH)
				syslog (LOG_INFO,
				    "detected a TID change[%#04hhx->%#04hhx]"
				    " in the same pid[%#06hx].\n",
				    sec->buf[0], p[0], pid);
			free(sec->priv);
			sec->priv = NULL;
		}

		sec->len = ((p[1] & 0x0f) << 8) + p[2] + 3;
		if (sec->len > sizeof(sec->buf))
			break;

		sec->buflen = 0;
		sec->start_cc = cc;
		sec->last_cc = cc;

		len = buf + 188 - p;
		if (sec->len < len)
			len = sec->len;

		memcpy(sec->buf, p, len);
		sec->buflen = len;

		if (len == sec->len) {
			section_cb(priv, pid);
			sec->last_cc = CC_NONE;
		}
		p += len;
	}
	return;
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
	if (ecm->kinfo.status != CMD_S_VOID &&
		ecm->kinfo.status != CMD_S_QUERYING &&
		ecm->kinfo.status != CMD_S_FAILED)
		demulti2(p, len, &card->param,
			ecm->kinfo.wrk[(buf[3] & TS_CA_MASK) == TS_CA_EVEN]);
	pthread_mutex_unlock(&card->lock);

	buf[3] &= ~TS_CA_MASK;
	return;

noscrambled:
	syslog(LOG_DEBUG, "packet CA flag is set but PMT denies.\n");
	return;

notready:
	syslog(LOG_DEBUG, " BCAS is not yet ready for de-scrambling.\n");
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
			advance(&priv->outbuf_head, sizeof(priv->outbuf), len);
		}
		advance(&priv->outbuf_tail, sizeof(priv->outbuf), len);
	} else {
		l = sizeof(priv->outbuf) - priv->outbuf_tail;
		if (l >= len)
			memcpy(priv->outbuf + priv->outbuf_tail, buf, len);
		else {
			memcpy(priv->outbuf + priv->outbuf_tail, buf, l);				memcpy(priv->outbuf, buf + l, len - l);
			if (len -l >= priv->outbuf_head) {
				syslog(LOG_DEBUG, "outbuf overflowed.\n");
				advance(&priv->outbuf_head,
					sizeof(priv->outbuf), len);
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
	int ret;
	void (*section_cb)(struct stream_priv *, uint16_t);
	int i, j;
	struct section *sec;
	struct pmt *pmt;

	if (buf[1] & TS_F_TSEI)
		return;

	pid = (buf[1] & 0x1f) << 8 | buf[2];
	if (pid == PID_NONE)
		return;

	/* if PSI that requires text conversion, */
	/* defer the output until section end */
	section_cb = NULL;

#if HAVE_ICONV_H
	if (priv->fs_priv->conv && pid == PID_NIT)
		section_cb = convert_nit;
	else if (priv->fs_priv->conv && pid == PID_SDT)
		section_cb = convert_sdt;
	else if (priv->fs_priv->eit && pid == PID_EITH)
		section_cb = convert_eith;

	if (section_cb != NULL) {
		push_section(priv, buf, section_cb);
		return; // not copy to the priv->outbuf here.
	}
#endif

	if (pid == PID_PAT)
		section_cb = parse_pat;
	else if (pid == PID_CAT && priv->fs_priv->emm)
		section_cb = parse_cat;
	else if (pid >= 0x002a) {
		/* check non-fixed-pid PSI: PMT,ECM,EMM */
		if (priv->cat.ver != VER_NONE) {
			for (i = 0; i< priv->cat.num_cas; i++) {
				if (priv->cat.emm[i].pid == pid &&
				    priv->cat.emm[i].pid != PID_NONE &&
				    priv->cat.emm[i].cas_id == priv->fs_priv->card.cas_id) {
					section_cb = parse_emm;
					goto done;
				}
			}
		}

		if (priv->pat.ver == VER_NONE) {
#if REPLACE_WITH_NULL
			buf[1] |= 0x1f;
			buf[2] = 0xff;
			buf[3] &= ~TS_CA_MASK;
			goto done;
#else
			return; // avoid non-scrambled 1seg program comes out 1st
#endif
		}

		for (i = 0; i < priv->pat.num_prog; i++) {
			if (priv->pat.program[i].prog_id == 0)
				continue;
			if (priv->pat.program[i].pmt_pid == pid) {
				section_cb = parse_pmt;
				goto done;
			}
			sec = priv->sections[priv->pat.program[i].pmt_pid];
			if (sec == NULL)
				continue;
			if (sec->priv == NULL)
				continue;
			pmt = sec->priv;
			if (pmt->ver == VER_NONE)
				continue;
			if (pmt->prog_ecm.pid == pid &&
			    pmt->prog_ecm.pid != PID_NONE) {
				section_cb = parse_ecm;
				goto done;
			}
			for (j = 0; j < pmt->num_es; j++) {
				if (pmt->es[j].es_pid == pid) {
					if (buf[3] & TS_CA_MASK)
						descramble(priv, buf,
						    &pmt->prog_ecm,
						    &pmt->es[j].es_ecm);
					if (buf[3] & TS_CA_MASK) {
#if REPLACE_WITH_NULL
						buf[1] |= 0x1f;
						buf[2] = 0xff;
						buf[3] &= ~TS_CA_MASK;
#else
						return;
#endif
					}
					goto done;
				}
				if (pmt->es[j].es_ecm.pid == pid &&
				    pmt->es[j].es_ecm.pid != PID_NONE &&
				    pmt->es[j].es_ecm.pid != 0) {
					section_cb = parse_ecm;
					goto done;
				}
			}
		}
	}

done:
	if (section_cb != NULL)
		push_section(priv, buf, section_cb);

	push_outbuf(priv, buf, 188);
	return;
}


static void *
fetch_loop(void *data)
{
	struct stream_priv *priv = (struct stream_priv *)data;
	int res;
	uint8_t *p;
	int min_read;
	int len;


	min_read = MAX_SCAN_LEN;
	while (1) {
		/* read from dvr0 dev */
		p = priv->inbuf + priv->inbuf_len;
		do {
			res = (int)read(priv->fd, p,
					sizeof(priv->inbuf) - priv->inbuf_len);
if (res < 1024) fprintf(stderr, "R%d\n", res);
			p += res;
			priv->inbuf_len += res;
		} while (res > 0 && priv->inbuf_len < min_read);

		if (res <= 0)
			goto failed;

		p = priv->inbuf;
		len = priv->inbuf_len;

		if (priv->packet_size == 0) {
			res = get_packet_size(priv);
			if (res < 0) {
				errno = EIO;
				goto failed;
			} else {
				min_read = priv->packet_size;
				p += res;
				len -= res;
			}
		}

		sched_yield();
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
//				fuse_pollhandle_destroy(priv->ph);
//				priv->ph = NULL;
			}
			pthread_cond_signal(&priv->buf_cond);
		}
		pthread_mutex_unlock(&priv->buf_lock);

		/* move the remainder fragment to the head */
		if (len > 0)
			memcpy(priv->inbuf, p, len);
		priv->inbuf_len = len;
	}
		
failed:
	pthread_mutex_lock(&priv->buf_lock);
	if (errno == 0)
		errno = EIO;
	priv->err = errno;
	pthread_cond_signal(&priv->buf_cond);
	pthread_mutex_lock(&priv->buf_lock);
	return NULL;
}



/* exported functions */

int
init_stream(struct stream_priv *priv)
{
	int res;
	iconv_t cd;

	priv->pat.ver = VER_NONE;
	priv->cat.ver = VER_NONE;

	pthread_mutex_init(&priv->buf_lock, NULL);
	pthread_cond_init(&priv->buf_cond, NULL);
	res = pthread_create(&priv->fetch_thread, NULL, fetch_loop, priv);
	if (res != 0)
		return -errno;

	if (priv->fs_priv->conv == 0 && priv->fs_priv->eit == 0)
		return 0;

	priv->iconv_cd = iconv_open("UTF-8//TRANSLIT", "EUC-JISX0213");
	if (priv->iconv_cd == (iconv_t)-1) {
		syslog(LOG_INFO,
		       "text conv. disabled by the failed iconv_open():%m\n");
		priv->fs_priv->conv = 0;
	}
	return 0;
}


void
release_stream(struct stream_priv *priv)
{
	int i;

	if (!pthread_cancel(priv->fetch_thread)) {
		pthread_mutex_unlock(&priv->buf_lock);
		pthread_join(priv->fetch_thread, NULL);
	}

	if (priv->fs_priv->conv && priv->iconv_cd != (iconv_t)-1)
		iconv_close(priv->iconv_cd);

	for (i = 0; i < 8192; i++)
		if (priv->sections[i] != NULL) {
			if (priv->sections[i]->priv != NULL)
				free(priv->sections[i]->priv);
			free(priv->sections[i]);
		}
}
