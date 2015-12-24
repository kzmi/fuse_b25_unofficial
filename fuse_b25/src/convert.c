/*
 * convert.c: converts the text in EIT, SDT, NIT, ... section into UTF-8,
 *             delays the output and insert them later.
 * Copyright 2011 0p1pp1
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
#include "convert.h"

#ifdef NO_SYSLOG
#define syslog(a, args...) fprintf(stderr, args...)
#endif

#define min(a, b) (((a) < (b)) ? (a) : (b))

#define DESC_NETWORK_NAME 0x40
#define DESC_TS_INFO 0xcd
#define DESC_SERVICE 0x48
#define DESC_CA_CONTRACT 0xcb
#define DESC_SHORT_EVENT 0x4d
#define DESC_COMPONENT 0x50
#define DESC_CONTENT 0x54
#define DESC_AUDIO_COMPONENT 0xc4
#define DESC_COMPONENT_GROUP 0xd9
#define DESC_SERIES 0xd5
#define DESC_EXTENDED_EVENT 0x4e

static const uint8_t genre_table[256] = {
	/* 0x0(News/Reports) -> 0x2(News/Current Affairs) */
	0x20, 0x21, 0x23, 0x20, 0x20, 0x20, 0x20, 0x24,
	0x20, 0x20, 0x20, 0x2F, 0x2F, 0x2F, 0x2F, 0x2F,
	/* 0x1(Sports) -> 0x4(Sports) */
	0x40, 0x40, 0x43, 0x40, 0x45, 0x4B, 0x41, 0x46,
	0x47, 0x49, 0x4A, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F,
	/* 0x2(Info./Wide show) -> 0xA(Leisure hobbies) */
	0x30, 0x7B, 0xA0, 0xA4, 0xA6, 0xA5, 0xA0, 0xA6,
	0xAF, 0xAF, 0xAF, 0xAF, 0xAF, 0xAF, 0xAF, 0xAF,
	/* 0x3(Drama) -> 0x1(Movie/Drama) */
	0x10, 0x10, 0x17, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F,
	0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F,
	/* 0x4(Music) -> 0x6(Music/Ballet/Dance) */
	0x61, 0x61, 0x62, 0x64, 0x63, 0x60, 0x60, 0x60,
	0x63, 0x60, 0x60, 0x6F, 0x6F, 0x6F, 0x6F, 0x6F,
	/* 0x5(Variety) -> 0x3(Show/Game show) */
	0x31, 0x31, 0x33, 0x30, 0x30, 0x30, 0x30, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	/* 0x6(Movie) -> 0x1(Movie/Drama) */
	0x10, 0x10, 0x55, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F,
	0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F,
	/* 0x7(Animation) -> 0x55(Childlen's/Youth programmes:cartoon/puppets) */
	0x55, 0x55, 0x55, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F,
	0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F,
	/* 0x8(Documentary/Culture) -> 0x7(Arts/Culture) */
	0x81, 0x90, 0x91, 0x92, 0x74, 0x75, 0x40, 0x23,
	0x24, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
	/* 0x9(Theater/Show) -> 0x6(Music/Ballet/Dance)? */
	0xF0, 0x65, 0x66, 0xF0, 0xF0, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	/* 0xA(Hobbies/Education) -> 0xA(Leisure hobbies) */
	0xA1, 0xA7, 0x70, 0xA0, 0xA0, 0xA3, 0xA0, 0x97,
	0x50, 0x50, 0x50, 0x96, 0x90, 0x9F, 0x9F, 0x9F,
	/* 0xB(Welfare) -> 0xF0(NONE) */
	0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const uint32_t crc_tab[256] = {
  0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
  0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd, 0x4c11db70, 0x48d0c6c7,
  0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
  0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58, 0xbaea46ef,
  0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb,
  0xceb42022, 0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
  0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4,
  0x0808d07d, 0x0cc9cdca, 0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
  0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc,
  0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050,
  0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
  0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb, 0x4f040d56, 0x4bc510e1,
  0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
  0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e, 0xf5ee4bb9,
  0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd,
  0xcda1f604, 0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
  0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2,
  0x470cdd2b, 0x43cdc09c, 0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
  0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a,
  0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676,
  0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
  0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

/* relicenced to LGPL from fluendo ts demuxer */
static uint32_t
calc_crc32 (uint8_t * data, uint datalen)
{
  int i;
  uint32_t crc = 0xffffffff;

  for (i = 0; i < datalen; i++) {
    crc = (crc << 8) ^ crc_tab[((crc >> 24) ^ *data++) & 0xff];
  }
  return crc;
}


/*
 * for text conversion of EIT,NIT,SDT,....
 * output is deferred until the section end,
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

	//sec->last_cc = CC_NONE;
	//sec->buflen = 0;
	return;
}

static int
convert_text(uint8_t **src, int len, int *sleft, uint8_t **dst, int *dleft,
	int max, iconv_t cd)
{
	int res;

	res = aribstr_to_utf8(cd, (char *)*src, len, (char *)*dst, min(*dleft, max));
	if (res < 0) {
		syslog(LOG_DEBUG, "failed to convert text in SI table.\n");
		res = min(len, min(*dleft, max));
		// memcpy(*dst, *src, res);
	}
	*src += len;
	*sleft -= len;
	*dst += res;
	*dleft -= res;
/*
	if (res > 0)
		syslog(LOG_DEBUG, "converted text:%s[%d]\n", *dst, res);
*/

	return res;
}

/*
 * convert texts, rewrites each descriptor's length and
 * returns total loop length.
 */
static int
convert_descriptors(uint8_t *src, int sleft, uint8_t *dst, int size,
	iconv_t cd)
{
	int dleft = size;
	uint8_t id, l, l2;
	int res;
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
			*p = convert_text(&src, l, &sleft, &dst, &dleft, 253, cd);
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
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 64, cd);
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
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 250, cd);
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
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 253 - *p, cd);
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
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 253 - *p, cd);
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
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 192, cd);
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
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 253 - *p, cd);
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

			res = convert_text(&src, l, &sleft, &dst, &dleft, 247, cd);
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

			res = convert_text(&src, l, &sleft, &dst, &dleft, 253 - *p, cd);
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
						min(48, 253 - *p), cd);
				l -= l2;
				*p += res;
				*(dst - res - 1) = res;
			}
			if (l != 0)
				goto failed; 
			break;
		case DESC_CONTENT:
			desc = "content";
			while (l >= 2 && sleft >= 2 && dleft >= 2) {
				if (*src < 0xC0)
					*dst++ = genre_table[*src++];
				else
					*dst++ = *src++;
				*dst++ = *src++;
				(*p) += 2;
				l -= 2;
				sleft -= 2;
				dleft -= 2;
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

			res = convert_text(&src, l, &sleft, &dst, &dleft, 253 - *p, cd);
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
						min(48, 251 - *p), cd);
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
						252 - *p, cd);
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
			res = convert_text(&src, l2, &sleft, &dst, &dleft, 253 - *p, cd);
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

	if (sleft != 0 || dleft < 0)
		goto failed;
	return size - dleft;

failed:
	syslog(LOG_DEBUG, "bad data for %s desc.\n", desc);
	return -1;
}


int
do_convert_nit(uint8_t *src, size_t slen, uint8_t *dst, size_t dlen, iconv_t cd)
{
	uint8_t *p, *q;
	int seclen;
	int looplen;
	int l, ol;
	int res;
	int dl;
	uint32_t crc;

	p = src;
	q = dst;
	ol = dlen;

	memcpy(q, p, 8);
	p += 8;
	q += 8;
	ol -= 8;

	l = (p[0] & 0x0f) << 8 | p[1];
	if (l + 2 + 2 > slen - 12)
		return -1;
	p += 2;

	res = convert_descriptors(p, l, q + 2, ol - 2, cd);
	if (res < 0)
		return -2;
	p += l;
	q[0] = (res & 0x0f00) >> 8 | 0xf0;
	q[1] = res & 0xff;
	q += 2 + res;
	ol -= 2 + res;

	if (p + 2 > src + slen || ol < 2)
		return -1;

	l = (p[0] & 0x0f) << 8 | p[1];
	p += 2;
	ol -= 2;
	if (p + l + 4 > src + slen)
		return -1;

	looplen = 0;
	while (l >= 6 && ol >= 6) {
		memcpy(q + looplen + 2, p, 6);
		dl = (p[4] & 0x0f) << 8 | p[5];
		looplen += 6;
		p += 6;
		l -= 6;
		ol -= 6;
		if (dl > l)
			return -1;
		res = convert_descriptors(p, dl, q + looplen + 2, ol, cd);
		if (res < 0)
			return -2;
		p += dl;
		l -= dl;
		q[looplen] = (res & 0x0f00) >> 8 | 0xf0;
		q[looplen + 1] = res & 0xff;
		looplen += res;
		ol -= res;
	}
	if (l != 0 || ol < 4)
		return -1;
	q[0] = (looplen & 0x0f00) >> 8 | 0xf0;
	q[1] = looplen & 0xff;
	q += looplen + 2;

	/* CRC (+ stuffing bytes) should be left */
	if (p + 4 > src + slen)
		return -1;
	memset(q, 0, 4);
	q += 4;

	seclen = q - dst - 3;
	/* write back */
	q = dst;
	q[1] = (seclen & 0x0f00) >> 8 | 0xb0;
	q[2] = seclen & 0xff;
	crc = calc_crc32(dst, seclen + 3 - 4);
	q = dst + seclen + 3 - 4;
	q[0] = (crc & 0xff000000) >> 24;
	q[1] = (crc & 0x00ff0000) >> 16;
	q[2] = (crc & 0x0000ff00) >> 8;
	q[3] = crc & 0xff;
	return 0;
}


/*
 * rewrites loop-length field & section-length after text conversion
 */
void
convert_nit(struct stream_priv *priv, uint16_t pid)
{
	struct section *sec;
	uint8_t *p, *q;
	int ver;

	sec = priv->sections[pid];
	p = sec->buf;
	q = sec->priv;

	if (*p != TID_NIT_SELF || sec->len < 16)
		goto bailout;

	ver = (sec->buf[5] & 0x3e) >> 1;
	if (q != NULL)
		if (ver == (q[5] & 0x3e) >> 1 && sec->buf[6] == q[6]) {
			q += ((q[1] & 0x0f) << 8) + q[2] + 3;
			goto done; // already processed NIT
		}

	if (q == NULL) {
		q = sec->priv = calloc(1, 2048);
		if (q == NULL) {
			syslog(LOG_INFO, "failed to alloc mem for NIT.\n");
			return;
		}
	}

	if (do_convert_nit(p, sec->len, q, 2048, priv->iconv_cd))
		goto bailout;

done:
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

int
do_convert_sdt(uint8_t *src, size_t slen, uint8_t *dst, size_t dlen, iconv_t cd)
{
	int seclen;
	uint8_t *p, *q;
	int l, ol;
	int res;
	int dl;
	uint32_t crc;

	p = src;
	q = dst;
	ol = dlen;
	l = slen - 4;

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
			return -1;
		res = convert_descriptors(p, dl, q, ol, cd);
		if (res < 0)
			return -2;
		*(q - 2) = 0xf0;
		*(q - 2) |= (res & 0x0f00) >> 8;
		*(q - 1) = res & 0xff;
		p += dl;
		l -= dl;
		q += res;
		ol -= res;
	}

	/* CRC (+ stuffing bytes) should be left */
	if (l < 0 || ol < 4)
		return -1;
	memset(q, 0, 4);
	q += 4;

	seclen = q - dst - 3;
	/* write back */
	q = dst;
	q[1] = (seclen & 0x0f00) >> 8 | 0xb0;
	q[2] = seclen & 0xff;
	crc = calc_crc32(dst, seclen + 3 - 4);
	q = dst + seclen + 3 - 4;
	q[0] = (crc & 0xff000000) >> 24;
	q[1] = (crc & 0x00ff0000) >> 16;
	q[2] = (crc & 0x0000ff00) >> 8;
	q[3] = crc & 0xff;
	return 0;
}

void
convert_sdt(struct stream_priv *priv, uint16_t pid)
{
	struct section *sec;
	uint8_t *p, *q;
	int ver;

	sec = priv->sections[pid];
	p = sec->buf;
	q = sec->priv;

	if ((*p != TID_SDT_SELF && *p != TID_SDT_OTHERS) || sec->len < 15)
		goto bailout;

	ver = (sec->buf[5] & 0x3e) >> 1;
	if (q != NULL)
		if (*p == q[0] && ver == (q[5] & 0x3e) >> 1
		    && sec->buf[6] == q[6]) {
			q += ((q[1] & 0x0f) << 8) + q[2] + 3;
			goto done; // already processed SDT
		}

	if (q == NULL) {
		q = sec->priv = calloc(1, 2048);
		if (q == NULL) {
			syslog(LOG_INFO, "failed to alloc mem for SDT.\n");
			return;
		}
	}

	if (do_convert_sdt(p, sec->len, q, 2048, priv->iconv_cd))
		goto bailout;

done:
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


int
do_convert_eit(uint8_t *src, size_t slen, uint8_t *dst, size_t dlen,
	int conv_utc, int conv_txt, iconv_t cd)
{
	int seclen;
	uint8_t *p, *q;
	int l, ol;
	int res;
	int dl;

	p = src;
	q = dst;
	ol = dlen;
	l = slen -4;

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
		if (conv_utc) {
			unsigned int mjd;
			unsigned int hour;
			/* convert the start-time in JST to UTC */

			mjd = q[2] << 8 | q[3];
			hour = (q[4] >> 4) * 10 + (q[4] & 0x0f);
			if (hour != 0x0f * 10 + 0x0f) {
				if (hour < 9) {
					hour += 24 - 9;
					mjd--;
				} else
					hour -= 9;
				q[2] = (mjd & 0xff00) >> 8;
				q[3] = mjd & 0xff;
				q[4] = (hour / 10) << 4 | (hour % 10);
			}
		}

		dl = (p[10] & 0x0f) << 8 | p[11];
		p += 12;
		l -= 12;
		q += 12;
		ol -= 12;
		if (l < dl )
			return -1;
		if (conv_txt)
			res = convert_descriptors(p, dl, q, ol, cd);
		else {
			memcpy(q, p, dl);
			res = dl;
		}
		if (res < 0) {
			syslog(LOG_NOTICE, "bad data/overflow in EIT."
				" discarding the rest.\n");
			p -= 12;
			q -= 12;
			ol += 12;
			goto done;
		}
		*(q - 2) = 0xf0;
		*(q - 2) |= (res & 0x0f00) >> 8;
		*(q - 1) = res & 0xff;
		p += dl;
		l -= dl;
		q += res;
		ol -= res;
	}

	/* only CRC should be left */
	if (l != 0)
		return -1;

done:
	if (ol >= 4) {
		memset(q, 0, 4);
		q += 4;
	}
	seclen = q - dst - 3;
	/* write back */
	q = dst;
	q[1] = (seclen & 0x0f00) >> 8 | 0xb0;
	q[2] = seclen & 0xff;
	if (ol >= 4) {
		uint32_t crc;

		crc = calc_crc32(dst, seclen + 3 - 4);
		q = dst + seclen + 3 - 4;
		q[0] = (crc & 0xff000000) >> 24;
		q[1] = (crc & 0x00ff0000) >> 16;
		q[2] = (crc & 0x0000ff00) >> 8;
		q[3] = crc & 0xff;
	}
	return 0;
}

void
convert_eith(struct stream_priv *priv, uint16_t pid)
{
	struct section *sec;
	uint8_t *p, *q;
	int ver;

	sec = priv->sections[pid];
	p = sec->buf;
	q = sec->priv;

	if (*p < TID_EITH_MIN || *p > TID_EITH_MAX || sec->len < 18)
		goto bailout;

	ver = (sec->buf[5] & 0x3e) >> 1;
	if (q != NULL)
		if (*p == q[0] && ver == (q[5] & 0x3e) >> 1 &&
		    sec->buf[6] == q[6]) {
			q += ((q[1] & 0x0f) << 8) + q[2] + 3 - 4;
			goto done; // already processed EIT
		}

	if (q == NULL) {
		q = sec->priv = calloc(1, 4096);
		if (q == NULL) {
			syslog(LOG_INFO, "failed to alloc mem for EIT.\n");
			return;
		}
	}

	if (do_convert_eit(p, sec->len, q, 4096,
		priv->fs_priv->utc, priv->fs_priv->eit, priv->iconv_cd))
		goto bailout;

done:
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

