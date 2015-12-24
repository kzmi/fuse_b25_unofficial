/*
 *  demuli2.h: MULTI2 Descrambler for BCAS
 *
 *  Copyright (C) 2009 0p1pp1 
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.=
 */
#ifndef _DEMULTI2_H_
#define _DEMULTI2_H_

#include <config.h>
#include <stdint.h>
#include <arpa/inet.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct u32x2 {
#ifndef WORDS_BIGENDIAN
	u32 r;
	u32 l;
#else
	u32 l;
	u32 r;
#endif
} __attribute__ ((packed)) CORE_DATA;


union demulti2_key {
	u64 whole;
	CORE_DATA sub;
};


struct demulti2_key_info {
	union demulti2_key k_scr[2]; /* k_scr[0]:odd,  k_scr[1]:even */
	u32 wrk[2][8]; /*wrk[0][]:odd,  wrk[1][]:even */
	enum {
	  CMD_S_VOID,
	  CMD_S_QUERYING,
	  CMD_S_UPDATING,
	  CMD_S_FAILED,
	  CMD_S_OK
	} status;
};


struct demulti2_param {
	int round;
	u32 k_sys[8];
	union demulti2_key cbc_init;
};

#define ntohll(a) htonll((a))
extern u64 htonll(u64 a);

extern void core_schedule(u32 *work, u32 *skey, CORE_DATA *dkey);
extern void demulti2(u8 *buf, size_t n, struct demulti2_param *param, u32 *wrk);

#endif // _DEMULTI2_H_
