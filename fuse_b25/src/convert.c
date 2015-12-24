/*
 * convert.c: converts the text in EIT, SDT, NIT, ... section into UTF-8,
 *             delays the output and insert them later.
 * Copyright 2009 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <iconv.h>

#include "stream.h"

#ifdef NO_SYSLOG
#define syslog(a, args...) fprintf(stderr, args...)
#endif

#define min(a, b) (((a) < (b)) ? (a) : (b))

#define TID_NIT_SELF 0x40
#define TID_SDT 0x42
#define TID_EITH_MIN 0x4e
#define TID_EITH_MAX 0x6f

#define DESC_NETWORK_NAME 0x40
#define DESC_TS_INFO 0xcd
#define DESC_SERVICE 0x48
#define DESC_CA_CONTRACT 0xcb
#define DESC_SHORT_EVENT 0x4d
#define DESC_COMPONENT 0x50
#define DESC_AUDIO_COMPONENT 0xc4
#define DESC_COMPONENT_GROUP 0xd9
#define DESC_SERIES 0xd5
#define DESC_EXTENDED_EVENT 0x4e

/* imported function from b24str.c */
extern int aribstr_to_utf8 (iconv_t cd, char *source, size_t len,
			    char *dest, size_t buf_len);

static iconv_t cd;

/*
 * for text conversion of EIT,NIT,SDT,....
 * output is deffered until the section end,
 * because the section length changes after conversion.
 * this func re-packetizes the converted section and write to priv->outbuf
 */

/* FIXME:a multi-sectioned packet is split to multiple (1 sectioned) packtes */
static void
output_section(struct stream_priv *priv, uint16_t pid)
{
	struct section *sec;
	uint8_t *buf;
	uint8_t header[5];
	uint8_t stuff[184];
	int len;
	int l;

	sec = priv->sections[pid];
	buf = sec->priv;
	len = ((buf[1] & 0x0f) << 8 | buf[2]) + 3;

	memset(stuff, 0xff, sizeof(stuff));

	header[0] = 0x47;
	header[1] = (pid & 0x1f00) >> 8;
	header[1] |= TS_F_PUSI;
	header[2] = (pid & 0xff);
	header[3] = 0x10 | sec->start_cc;  // no CA, no adapt.field, payload
	header[4] = 0x00;

	l = 183;
	if (len < l)
		l = len;

	push_outbuf(priv, header, 5);
	push_outbuf(priv, buf, l);
	if (l < 183)
		push_outbuf(priv, stuff, 183 - l); 

	len -= l;
	buf += l;
	if (++header[3] == 0x20)
		header[3] = 0x10;

	header[1] &= ~TS_F_PUSI;
	while (len >= 184) {
		push_outbuf(priv, header, 4);
		push_outbuf(priv, buf, 184);
		len -= 184;
		buf += 184;
		if (++header[3] == 0x20)
			header[3] = 0x10;
	}

	if (len > 0) {
		push_outbuf(priv, header, 4);
		push_outbuf(priv, buf, len);
		push_outbuf(priv, stuff, 184 - len);
	}

	sec->last_cc = CC_NONE;
	sec->buflen = 0;
	return;
}

static int
convert_text(uint8_t **src, int len, int *sleft, uint8_t **dst, int *dleft, int max)
{
	int res;
	uint8_t *p = *dst;

	res = aribstr_to_utf8(cd, *src, len, *dst, min(*dleft, max));
	*src += len;
	*sleft -= len;
	if (res < 0) {
		syslog(LOG_DEBUG, "failed to convert text in SI table.\n");
		res = min(len, max);
	}
	*dst += res;
	*dleft -= res;
/*
	if (res > 0)
		syslog(LOG_DEBUG, "converted text:%s[%d]\n", p, res);
*/

	return res;
}

/*
 * convert texts, rewrites each descriptor's length and
 * returns total loop length.
 */
static int
convert_descriptors(uint8_t *src, int sleft, uint8_t *dst, int size)
{
	int dleft = size;
	uint8_t id, l, l2;
	int res;
	uint8_t newlen;
	uint8_t *p, *q, *e;
	int i, j, n;
	const char *desc = "";

	while (sleft >= 2 && dleft >= 2) {
		id = *(dst++) = *(src++);
		l = *(src++);
		p = dst++;
		sleft -= 2;
		dleft -= 2;
		*p = 0;
		if (l > sleft)
			goto failed;

		switch (id) {
		case DESC_NETWORK_NAME:
			desc = "network name";
			*p = convert_text(&src, l, &sleft, &dst, &dleft, 253);
			break;
		case DESC_TS_INFO:
			desc = "TS info";
			if (l < 2 || dleft < 2)
				goto failed;
			dst[0] = src[0];
			dst[1] = src[1] & 0x03;
			l2 = src[1] >> 2;
			src += 2;
			dst += 2;
			sleft -= 2;
			dleft -= 2;
			l -= 2;
			*p += 2;
			if (l < l2)
				goto failed;
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 64);
			*p += res;
			*(dst - res - 1) |= res << 2;
			l -= l2;
			if (l < 0 || dleft < l)
				goto failed;
			if (l > 0) {
				memcpy(dst, src, l);
				src += l;
				sleft -= l;
				dst += l;
				dleft -= l;
				*p += l;
			}
			break;
		case DESC_SERVICE:
			desc = "service";
			if (l < 3 || dleft < 3)
				goto failed;
			dst[0] = src[0];
			l2 = src[1];
			src += 2;
			dst += 2;
			sleft -= 2;
			dleft -= 2;
			l -= 2;
			*p += 2;

			if (l < l2 + 1 )
				goto failed;
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 250);
			*p += res;
			*(dst - res - 1) = res;
			l -= l2;

			if (dleft < 1)
				goto failed;
			l2 = *(src++);
			sleft--;
			dst++;
			dleft--;			
			l--;
			(*p)++;
			if (l < l2)
				goto failed;
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 253 - *p);
			*p += res;
			*(dst - res - 1) = res;
			break;
		case DESC_CA_CONTRACT:
			desc = "CA contract info";
			if (l < 5 || dleft < 5)
				goto failed;
			l2 = 2;
			l2 += (src[l2] & 0x0f) + 1;
			if (l < l2 || dleft < l2)
				goto failed;
			l2 += src[l2] + 1;
			if (l < l2 || dleft < l2)
				goto failed;
			memcpy(dst, src, l2);
			src += l2;
			sleft -= l2;
			dst += l2;
			dleft -= l2;
			l -= l2;
			*p += l2;

			if (l < 1 || dleft < 1)
				goto failed;
			l2 = src[0];
			src++;
			sleft--;
			dst++;
			dleft--;
			l--;
			(*p)++;
			if (l2 != l) {
				memcpy(dst, src, l);
				src += l;
				sleft -= l;
				dst += l;
				dleft -= l;
				*p += l;
				break;
			}
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 253 - *p);
			*p += res;
			*(dst - res - 1) = res;
			break;
		case DESC_SHORT_EVENT:
			desc = "short event";
			if (l < 5 || dleft < 5)
				goto failed;
			memcpy(dst, src, 3);
			src += 3;
			l2 = *(src++);
			sleft -= 4;
			dst += 4;
			dleft -= 4;
			l -= 4;
			*p += 4;

			if (l < l2 + 1)
				goto failed;
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 192);
			*p += res;
			*(dst - res - 1) = res;
			l -= l2;

			if (dleft < 1)
				goto failed;
			l2 = *(src++);
			sleft--;
			dst++;
			dleft--;			
			l--;
			(*p)++;

			if (l < l2) {
				goto failed;
			}
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 253 - *p);
			*p += res;
			*(dst - res - 1) = res;
			break;
		case DESC_COMPONENT:
			desc = "component";
			if (l < 6 || dleft < 6)
				goto failed;
			memcpy(dst, src, 6);
			src += 6;
			dst += 6;
			sleft -= 6;
			dleft -= 6;
			l -= 6;
			*p += 6;

			res = convert_text(&src, l, &sleft, &dst, &dleft, 247);
			*p += res;
			break;
		case DESC_AUDIO_COMPONENT:
			desc = "audio component";
			if (l < 9 || dleft < 9)
				goto failed;
			l2 = 9;
			if (src[5] & 0x80)
				l2 += 3;
			if (l < l2 || dleft < l2)
				goto failed;
			memcpy(dst, src, l2);
			src += l2;
			dst += l2;
			sleft -= l2;
			dleft -= l2;
			l -= l2;
			*p += l2;

			res = convert_text(&src, l, &sleft, &dst, &dleft, 253 - *p);
			*p += res;
			break;
		case DESC_COMPONENT_GROUP:
			desc = "component group";
			if (l < 1 || dleft < 1)
				goto failed;
			n = src[0];
			dst[0] = src[0];
			src++;
			dst++;
			sleft--;
			dleft--;
			l--;
			(*p)++;

			for (i = 0; i < (n & 0x0f); i++) {
				l2 = 1;
				for (j = 0; j < (src[0] & 0x0f); j++)
					l2 += 1 + (src[l2] & 0x0f);
				if (n & 0x10)
					l2++;
				if (l < l2 || dleft < l2)
					goto failed;
				memcpy(dst, src, l2);
				src += l2;
				dst += l2;
				sleft -= l2;
				dleft -= l2;
				l -= l2;
				*p += l2;

				if (l < 1 || dleft < 1)
					goto failed;
				l2 = src[0];
				src ++;
				dst ++;
				sleft --;
				dleft --;
				l --;
				(*p) ++;

				if (l < l2 || *p > 253)
					goto failed;
				res = convert_text(&src, l2, &sleft, &dst, &dleft,
						min(48, 253 - *p));
				l -= l2;
				*p += res;
				*(dst - res - 1) = res;
			}
			if (l != 0)
				goto failed; 
			break;
		case DESC_SERIES:
			desc = "series";
			l2 = 8;
			if (l < l2 || dleft < l2)
				goto failed;
			memcpy(dst, src, l2);
			src += l2;
			dst += l2;
			sleft -= l2;
			dleft -= l2;
			l -= l2;
			*p += l2;

			res = convert_text(&src, l, &sleft, &dst, &dleft, 253 - *p);
			*p += res;
			break;
		case DESC_EXTENDED_EVENT:
			desc = "extended event";
			if (l < 6 || dleft < 6)
				goto failed;
			if (dleft < 6)
				break;
			l2 = 5;
			memcpy(dst, src, l2);
			src += l2;
			dst += l2;
			sleft -= l2;
			dleft -= l2;
			l -= l2;
			*p += l2;

			q = dst - 1;
			*q = 0;
			e = src + *(src - 1);
			while (src < e) {
				if (l < 1 || dleft < 1)
					goto failed;
				l2 = *(src++);
				dst++;
				sleft--;
				dleft--;
				l--;
				(*p)++;
				(*q)++;

				if (l < l2 || *p > 251)
					goto failed;
				res = convert_text(&src, l2, &sleft, &dst, &dleft,
						min(48, 251 - *p));
				l -= l2;
				*p += res;
				*q += res;
				*(dst - res - 1) = res;

				if (l < 1 || dleft < 1)
					goto failed;
				l2 = *(src++);
				dst++;
				sleft--;
				dleft--;
				l--;
				(*p)++;
				(*q)++;

				if (l < l2 || *p > 252)
					goto failed;
				res = convert_text(&src, l2, &sleft, &dst, &dleft,
						252 - *p);
				l -= l2;
				*p += res;
				*q += res;
				*(dst - res - 1) = res;
			}

			if (src != e || l < 1 || dleft < 1)
				goto failed;
			l2 = *(src++);
			dst++;
			sleft --;
			dleft --;
			l --;
			(*p) ++;

			if (l < l2 || *p > 253)
				goto failed;
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 253 - *p);
			*(dst - res - 1) = res;
			*p += res;
			break;
		default:
			desc = "";
			if (l > dleft)
				goto failed;
			memcpy(dst, src, l);
			src += l;
			sleft -= l;
			dst += l;
			dleft -= l;
			*p = l;
		}				
	}
done:
	if (sleft != 0 || dleft < 0)
		goto failed;
	return size - dleft;

failed:
	syslog(LOG_DEBUG, "bad data for %s desc.\n", desc);
	return -1;
}


/*
 * rewrites loop-length field & section-length after text conversion
 */
void
convert_nit(struct stream_priv *priv, uint16_t pid)
{
	struct section *sec;
	int seclen;
	int looplen;
	uint8_t *p, *q;
	int l, ol;
	int res;
	int dl;
	int ver;

	cd = priv->iconv_cd;
	sec = priv->sections[pid];
	p = sec->buf;
	q = sec->priv;
	ol = 1024 * 2;

	if (*p != TID_NIT_SELF || sec->len < 16)
		goto bailout;

	ver = (sec->buf[5] & 0x3e) >> 1;
	if (q != NULL)
		if (ver == (q[5] & 0x3e) >> 1 && sec->buf[6] == q[6]) {
			q += ((q[1] & 0x0f) << 8) + q[2] + 3;
			goto done; // already processed NIT
		}

	if (q == NULL) {
		q = sec->priv = calloc(1, ol);
		if (q == NULL) {
			syslog(LOG_INFO, "failed to alloc mem for NIT.\n");
			return;
		}
	}

	memcpy(q, p, 8);
	p += 8;
	q += 8;
	ol -= 8;

	l = (p[0] & 0x0f) << 8 | p[1];
	if (l + 2 + 2 > sec->len - 12)
		goto bailout;
	p += 2;

	res = convert_descriptors(p, l, q + 2, ol - 2);
	if (res < 0)
		goto bailout;
	p += l;
	q[0] = (res & 0x0f00) >> 8 | 0xf0;
	q[1] = res & 0xff;
	q += 2 + res;
	ol -= 2 + res;

	if (p + 2 > sec->buf + sec->len || ol < 2)
		goto bailout;

	l = (p[0] & 0x0f) << 8 | p[1];
	p += 2;
	ol -= 2;
	if (p + l + 4 > sec->buf + sec->len)
		goto bailout;

	looplen = 0;
	while (l >= 6 && ol >= 6) {
		memcpy(q + looplen, p, 6);
		dl = (p[4] & 0x0f) << 8 | p[5];
		looplen += 6;
		p += 6;
		l -= 6;
		ol -= 6;
		if (dl > l)
			goto bailout;
		res = convert_descriptors(p, dl, q + looplen, ol);
		if (res < 0)
			goto bailout;
		p += dl;
		l -= dl;
		q[looplen - 2] = (res & 0x0f00) >> 8 | 0xf0;
		q[looplen - 1] = res & 0xff;
		looplen += res;
		ol -= res;
	}
	if (l != 0 || ol < 4)
		goto bailout;
	q[0] = (looplen & 0x0f00) >> 8 | 0xf0;
	q[1] = looplen & 0xff;

	/* CRC (+ stuffing bytes) should be left */
	if (p + 4 > sec->buf + sec->len)
		goto bailout;
	memcpy(q, p, 4);
	q += 4;

done:
	seclen = (void *)q - sec->priv - 3;
	/* write back */
	q = sec->priv;
	q[1] = (seclen & 0x0f00) >> 8 | 0xb0;
	q[2] = seclen & 0xff;
	output_section(priv, pid);
	return;

bailout:
	if (sec->priv != NULL) {
		free(sec->priv);
		sec->priv = NULL;
	}
	syslog(LOG_INFO, "bad section data / data overlow for NIT.\n");
	return;
}

void
convert_sdt(struct stream_priv *priv, uint16_t pid)
{
	struct section *sec;
	int seclen;
	uint8_t *p, *q;
	int l, ol;
	int res;
	int dl;
	int ver;

	cd = priv->iconv_cd;
	sec = priv->sections[pid];
	p = sec->buf;
	l = sec->len -4;
	q = sec->priv;
	ol = 1024 * 2;

	if (*p != TID_SDT || l < 11)
		goto bailout;

	ver = (sec->buf[5] & 0x3e) >> 1;
	if (q != NULL)
		if (ver == (q[5] & 0x3e) >> 1 && sec->buf[6] == q[6]) {
			q += ((q[1] & 0x0f) << 8) + q[2] + 3;
			goto done; // already processed SDT
		}

	if (q == NULL) {
		q = sec->priv = calloc(1, ol);
		if (q == NULL) {
			syslog(LOG_INFO, "failed to alloc mem for SDT.\n");
			return;
		}
	}

	memcpy(q, p, 11);
	p += 11;
	q += 11;
	l -= 11;
	ol -= 11;

	while (l >= 5 && ol >= 5) {
		memcpy(q, p, 5);
		dl = (p[3] & 0x0f) << 8 | p[4];
		p += 5;
		l -= 5;
		q += 5;
		ol -= 5;
		if (dl > l )
			goto bailout;
		res = convert_descriptors(p, dl, q, ol);
		if (res < 0)
			goto bailout;
		*(q - 2) &= 0xf0;
		*(q - 2) |= (res & 0x0f00) >> 8;
		*(q - 1) = res & 0xff;
		p += dl;
		l -= dl;
		q += res;
		ol -= res;
	}

	/* CRC (+ stuffing bytes) should be left */
	if (l < 0 || ol < 4)
		goto bailout;
	memcpy(q, p, 4);
	q += 4;
done:
	seclen = (void *)q - sec->priv - 3;
	/* write back */
	q = sec->priv;
	q[1] = (seclen & 0x0f00) >> 8 | 0xb0;
	q[2] = seclen & 0xff;
	output_section(priv, pid);
	return;

bailout:
	if (sec->priv != NULL) {
		free(sec->priv);
		sec->priv = NULL;
	}
	syslog(LOG_INFO, "bad section data for SDT.\n");
	return;
}


void
convert_eith(struct stream_priv *priv, uint16_t pid)
{
	struct section *sec;
	int seclen;
	uint8_t *p, *q;
	int l, ol;
	int res;
	int dl;
	int ver;

	cd = priv->iconv_cd;
	sec = priv->sections[pid];
	p = sec->buf;
	l = sec->len -4;
	q = sec->priv;
	ol = 4096;

	if (*p < TID_EITH_MIN || *p > TID_EITH_MAX || l < 14)
		goto bailout;

	ver = (sec->buf[5] & 0x3e) >> 1;
	if (q != NULL)
		if (*p == q[0] && ver == (q[5] & 0x3e) >> 1 &&
		    sec->buf[6] == q[6]) {
			q += ((q[1] & 0x0f) << 8) + q[2] + 3 - 4;
			goto done; // already processed SDT
		}

	if (q == NULL) {
		q = sec->priv = calloc(1, 4096);
		if (q == NULL) {
			syslog(LOG_INFO, "failed to alloc mem for EIT.\n");
			return;
		}
	}

	memcpy(q, p, 14);
	p += 14;
	q += 14;
	l -= 14;
	ol -= 14;

	while (l >= 12) {
		if (ol < 12) {
			syslog(LOG_NOTICE, "overflow in EIT."
				" discarding the rest.\n");
			goto done;
		}
			
		memcpy(q, p, 12);
		dl = (p[10] & 0x0f) << 8 | p[11];
		p += 12;
		l -= 12;
		q += 12;
		ol -= 12;
		if (l < dl )
			goto bailout;
		res = convert_descriptors(p, dl, q, ol);
		if (res < 0) {
			syslog(LOG_NOTICE, "bad data/overflow in EIT."
				" discarding the rest.\n");
			p -= 12;
			q -= 12;
			goto done;
		}
		*(q - 2) &= 0xf0;
		*(q - 2) |= (res & 0x0f00) >> 8;
		*(q - 1) = res & 0xff;
		p += dl;
		l -= dl;
		q += res;
		ol -= res;
	}

	/* only CRC should be left */
	if (l != 0)
		goto bailout;

done:
	if (ol >= 4)
		q += 4; // useless CRC
	seclen = (void *)q - sec->priv - 3;
	/* write back */
	q = sec->priv;
	q[1] = (seclen & 0x0f00) >> 8 | 0xb0;
	q[2] = seclen & 0xff;
	output_section(priv, pid);
	return;

bailout:
	if (sec->priv != NULL) {
		free(sec->priv);
		sec->priv = NULL;
	}
	syslog(LOG_INFO, "bad section data for EIT.\n");
	return;
}

