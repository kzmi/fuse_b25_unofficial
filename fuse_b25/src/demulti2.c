#include "demulti2.h"

u64
htonll(u64 a)
{
	union demulti2_key res;
	u32 *p = (u32 *)&a;

	res.sub.l = htonl(p[0]);
	res.sub.r = htonl(p[1]);
	return res.whole;
}

static inline u32
left_rotate_uint32 (u32 val, u32 count)
{
  return ((val << count) | (val >> (32 - count)));
}

static void
core_pi1 (CORE_DATA * dst, CORE_DATA * src)
{
  dst->l = src->l;
  dst->r = src->r ^ src->l;
}

static void
core_pi2 (CORE_DATA * dst, CORE_DATA * src, u32 a)
{
  u32 t0, t1, t2;

  t0 = src->r + a;
  t1 = left_rotate_uint32 (t0, 1) + t0 - 1;
  t2 = left_rotate_uint32 (t1, 4) ^ t1;

  dst->l = src->l ^ t2;
  dst->r = src->r;
}

static void
core_pi3 (CORE_DATA * dst, CORE_DATA * src, u32 a, u32 b)
{
  u32 t0, t1, t2, t3, t4, t5;

  t0 = src->l + a;
  t1 = left_rotate_uint32 (t0, 2) + t0 + 1;
  t2 = left_rotate_uint32 (t1, 8) ^ t1;
  t3 = t2 + b;
  t4 = left_rotate_uint32 (t3, 1) - t3;
  t5 = left_rotate_uint32 (t4, 16) ^ (t4 | src->l);

  dst->l = src->l;
  dst->r = src->r ^ t5;
}

static void
core_pi4 (CORE_DATA * dst, CORE_DATA * src, u32 a)
{
  u32 t0, t1;

  t0 = src->r + a;
  t1 = left_rotate_uint32 (t0, 2) + t0 + 1;

  dst->l = src->l ^ t1;
  dst->r = src->r;
}


void
core_schedule (u32 * work, u32 * skey, CORE_DATA * dkey)
{
  CORE_DATA b1, b2, b3, b4, b5, b6, b7, b8, b9;

  core_pi1 (&b1, dkey);

  core_pi2 (&b2, &b1, skey[0]);
  work[0] = b2.l;

  core_pi3 (&b3, &b2, skey[1], skey[2]);
  work[1] = b3.r;

  core_pi4 (&b4, &b3, skey[3]);
  work[2] = b4.l;

  core_pi1 (&b5, &b4);
  work[3] = b5.r;

  core_pi2 (&b6, &b5, skey[4]);
  work[4] = b6.l;

  core_pi3 (&b7, &b6, skey[5], skey[6]);
  work[5] = b7.r;

  core_pi4 (&b8, &b7, skey[7]);
  work[6] = b8.l;

  core_pi1 (&b9, &b8);
  work[7] = b9.r;
}


static void
core_encrypt (CORE_DATA * dst, CORE_DATA * src, u32 * w, int round)
{
  int i;

  CORE_DATA tmp;

  dst->l = src->l;
  dst->r = src->r;
  for (i = 0; i < round; i++) {
    core_pi1 (&tmp, dst);
    core_pi2 (dst, &tmp, w[0]);
    core_pi3 (&tmp, dst, w[1], w[2]);
    core_pi4 (dst, &tmp, w[3]);
    core_pi1 (&tmp, dst);
    core_pi2 (dst, &tmp, w[4]);
    core_pi3 (&tmp, dst, w[5], w[6]);
    core_pi4 (dst, &tmp, w[7]);
  }
}


static void
core_decrypt (CORE_DATA * dst, CORE_DATA * src, u32 * w, int round)
{
  int i;

  CORE_DATA tmp;

  dst->l = src->l;
  dst->r = src->r;
  for (i = 0; i < round; i++) {
    core_pi4 (&tmp, dst, w[7]);
    core_pi3 (dst, &tmp, w[5], w[6]);
    core_pi2 (&tmp, dst, w[4]);
    core_pi1 (dst, &tmp);
    core_pi4 (&tmp, dst, w[3]);
    core_pi3 (dst, &tmp, w[1], w[2]);
    core_pi2 (&tmp, dst, w[0]);
    core_pi1 (dst, &tmp);
  }
}

void
demulti2 (u8 * buf, size_t len, struct demulti2_param *param, u32 * prm)
{
  union demulti2_key src, dst, cbc;

  cbc.whole = param->cbc_init.whole;

  while (len >= 8) {
    src.whole = ntohll (*(u64 *) buf);
    core_decrypt (&dst.sub, &src.sub, prm, param->round);
    dst.whole ^= cbc.whole;
    cbc.whole = src.whole;
    *(u64 *) buf = htonll (dst.whole);
    len -= 8;
    buf += 8;
  }

  if (len > 0) {
    int i;
    u64 t64;
    u8 *tmp = (u8 *) & t64;

    core_encrypt (&dst.sub, &cbc.sub, prm, param->round);
    t64 = htonll (dst.whole);

    for (i = 0; i < len; i++)
      buf[i] ^= tmp[i];
  }

  return;
}
