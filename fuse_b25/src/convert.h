/*
 * convert.h: converts the text in EIT, SDT, NIT, ... section into UTF-8,
 *             delays the output and insert them later.
 * Copyright 2011 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef _CONVERT_H_
#define _CONVERT_H_

#include <inttypes.h>
#include <string.h>
#include <iconv.h>

#include "stream.h"

#define TID_NIT_SELF 0x40
#define TID_NIT_OTHERS 0x41
#define TID_SDT_SELF 0x42
#define TID_SDT_OTHERS 0x46
#define TID_EITH_MIN 0x4e
#define TID_EITH_MAX 0x6f

/* imported function from b24str.c */
extern int aribstr_to_utf16 (iconv_t cd, char *source, size_t len,
			    char *dest, size_t buf_len);

/* text conversion utilities called both from stream.c & secfilter.c */
int do_convert_nit(uint8_t *src, size_t slen,
	uint8_t *dst, size_t dlen, iconv_t cd);
int do_convert_sdt(uint8_t *src, size_t slen,
	uint8_t *dst, size_t dlen, iconv_t cd);
int do_convert_eit(uint8_t *src, size_t slen, uint8_t *dst, size_t dlen,
	int conv_utc, int conv_txt, iconv_t cd);

/* text conversion related funcs (used from stream.c) */
extern void convert_nit(struct stream_priv *priv, uint16_t pid);
extern void convert_sdt(struct stream_priv *priv, uint16_t pid);
extern void convert_eith(struct stream_priv *priv, uint16_t pid);


#endif /* #ifndef _CONVERT_H_ */
