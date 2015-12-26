/*
 * secfilter.c: convert text data in PSI sections from demuxN
 * Copyright 2011 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */
#include <syslog.h>
#include <errno.h>
#include <pthread.h>

#include <poll.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/dvb/dmx.h>
#include <unistd.h>

#define FUSE_USE_VERSION 28
#include <fuse.h>

#ifdef NO_SYSLOG
#define syslog(a, args...) fprintf(stderr, args...)
#endif

#define TRUE 1

#include "convert.h"
#include "secfilter.h"

/* how long the filter_loop waits for data ready. [msec] */
#define SECFILTER_POLL_INTERVAL (200)

static uint8_t section_buf[MAX_SECTION_SIZE];

/* ring buffer related. 
 * copied and slightly modified from stream.c
 */
static inline void
advance(size_t *a, size_t size, size_t len)
{
	*a += len;
	if (*a >= size)
		*a -= size;
}

uint16_t
get_seclen(unsigned int idx, uint8_t *buf, size_t buf_size)
{
	uint16_t seclen;

	idx = (idx + 1) % buf_size;
	seclen = (buf[idx] & 0x0f) << 8;
	idx = (idx + 1) % buf_size;
	seclen += buf[idx] + 3;
	return seclen;
}

static unsigned int
skip_by_sections(struct secfilter_priv *priv, unsigned int min)
{
	unsigned int idx, l, seclen;

	idx = priv->outbuf_head;
	for (l = 0; l < min;) {
		seclen = get_seclen(idx, priv->outbuf, sizeof(priv->outbuf));
		l += seclen;
		idx = (idx + seclen) % sizeof(priv->outbuf);
	}
	return l;
}

static void
push_secbuf(struct secfilter_priv *priv, const uint8_t *buf, size_t len)
{
	unsigned int l;

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
			l = len - (priv->outbuf_head - priv->outbuf_tail) + 1;
			/* discard one or more section(s) */
			if (priv->stype != SECTION_TYPE_PES)
				l = skip_by_sections(priv, l);

			advance(&priv->outbuf_head, sizeof(priv->outbuf), l);
		}
		advance(&priv->outbuf_tail, sizeof(priv->outbuf), len);
	} else {
		l = sizeof(priv->outbuf) - priv->outbuf_tail;
		if (l > len)
			memcpy(priv->outbuf + priv->outbuf_tail, buf, len);
		else {
			memcpy(priv->outbuf + priv->outbuf_tail, buf, l);
			memcpy(priv->outbuf, buf + l, len - l);
			if (len - l >= priv->outbuf_head) {
				syslog(LOG_DEBUG, "outbuf overflowed.\n");
				l = len - l - priv->outbuf_head + 1;
				/* discard one or more section(s) */
				if (priv->stype != SECTION_TYPE_PES)
					l = skip_by_sections(priv, l);

				advance(&priv->outbuf_head,
					sizeof(priv->outbuf), l);
			}
		}
		advance(&priv->outbuf_tail, sizeof(priv->outbuf), len);
	}

	if (priv->ph) {
		fuse_notify_poll(priv->ph);
		fuse_pollhandle_destroy(priv->ph);
		priv->ph = NULL;
	}
	pthread_cond_signal(&priv->buf_cond);
	syslog(LOG_DEBUG, "secfilter output. len:%lu\n", len);
}

static void
direct_out(struct secfilter_priv *priv)
{
	unsigned int seclen;

	if (priv->stype == SECTION_TYPE_PES) {
		seclen = priv->inbuf_len;
		if (seclen > 0)
			goto output;
		return;
	}

	if (priv->inbuf_len < 3) {
		seclen = priv->inbuf_len;
		goto baddata;
	}
	seclen = ((priv->inbuf[1] & 0x0f) << 8 | priv->inbuf[2]) + 3;
	if (priv->inbuf_len < seclen)
		goto baddata;

output:
	push_secbuf(priv, priv->inbuf, seclen);
	return;

baddata:
	syslog(LOG_INFO, "demux read() returned broken data. seclen:%u\n",
	    seclen);
	return;
}

/* similar to convert.c::convert_nit(), but not in-place */
static void
convert_nit_sec(struct secfilter_priv *priv)
{
	unsigned int seclen = 0, newlen;
	uint8_t tid = priv->inbuf[0];

	if (priv->inbuf_len < 3)
		goto baddata;

	seclen = ((priv->inbuf[1] & 0x0f) << 8 | priv->inbuf[2]) + 3;
	if (priv->inbuf_len < seclen || seclen < 16 ||
	    (tid != TID_NIT_SELF && tid != TID_NIT_OTHERS) ||
	    do_convert_nit(priv->inbuf, priv->inbuf_len,
			section_buf, sizeof(section_buf), priv->iconv_cd))
		goto baddata;

	newlen = ((section_buf[1] & 0x0f) << 8 | section_buf[2]) + 3;
	push_secbuf(priv, section_buf, newlen);
	return;

baddata:
	syslog(LOG_INFO, "bad section data / overlow in NIT. seclen:%u\n",
	    seclen);
	return;
}

static void
convert_sdt_sec(struct secfilter_priv *priv)
{
	unsigned int seclen, newlen;
	uint8_t tid = priv->inbuf[0];

	if (priv->inbuf_len < 3) {
		seclen = priv->inbuf_len;
		goto baddata;
	}

	seclen = ((priv->inbuf[1] & 0x0f) << 8 | priv->inbuf[2]) + 3;
	if (priv->inbuf_len < seclen || seclen < 15 ||
	    (tid != TID_SDT_SELF && tid != TID_SDT_OTHERS) ||
	    do_convert_sdt(priv->inbuf, priv->inbuf_len,
			section_buf, sizeof(section_buf), priv->iconv_cd))
		goto baddata;

	newlen = ((section_buf[1] & 0x0f) << 8 | section_buf[2]) + 3;
	push_secbuf(priv, section_buf, newlen);
	return;

baddata:
	syslog(LOG_INFO, "bad section data / overlow in SDT. seclen:%u\n",
	    seclen);
	return;
}

static void
convert_eit_sec(struct secfilter_priv *priv)
{
	unsigned int seclen = 0, newlen;
	uint8_t tid = priv->inbuf[0];

	if (priv->inbuf_len < 3)
		goto baddata;

	seclen = ((priv->inbuf[1] & 0x0f) << 8 | priv->inbuf[2]) + 3;
	if (priv->inbuf_len < seclen || seclen < 18 ||
	    tid < TID_EITH_MIN || tid > TID_EITH_MAX ||
	    do_convert_eit(priv->inbuf, priv->inbuf_len, section_buf,
			sizeof(section_buf), TRUE, TRUE, priv->iconv_cd))
		goto baddata;

	newlen = ((section_buf[1] & 0x0f) << 8 | section_buf[2]) + 3;
	push_secbuf(priv, section_buf, newlen);
	return;

baddata:
	syslog(LOG_INFO, "bad section data / overlow in EIT. seclen:%u\n",
	    seclen);
	return;
}

static void
filter_loop_cleanup(void *data)
{
	struct secfilter_priv *priv = (struct secfilter_priv *)data;

//	pthread_mutex_trylock(&priv->filter_lock);
	pthread_mutex_unlock(&priv->filter_lock);
}

static void *
filter_loop(void *data)
{
	struct secfilter_priv *priv = (struct secfilter_priv *)data;
	struct pollfd pfd;
	int err = 0;
	enum sectype stype;

	pthread_cleanup_push(filter_loop_cleanup, data);

	pfd.fd = priv->fd;
	pfd.events = POLLIN;

	syslog(LOG_DEBUG, "filter_loop started. \n");

	while (1) {
		pthread_testcancel();
		pfd.revents = 0;
		err = poll(&pfd, 1, SECFILTER_POLL_INTERVAL);
		if (err < 0) {
			priv->err = errno;
			syslog(LOG_INFO, "failed to poll on demuxer.\n");
			break;
		} else if (err == 0)
			continue;

		/* data ready or error */
		/* error. */
		/* but don't bailout if POLLERR, */
		/*  which can indicate filter's timeout or broken data */
		if ((pfd.revents & POLLHUP) || (pfd.revents & POLLNVAL)) {
			syslog(LOG_INFO, "target device reported error.\n");
			break;
		}

		/* according to DVB API, if the buffer is large enough, */
		/* read() always returns the whole section */
		err = (int) read(pfd.fd, priv->inbuf, sizeof(priv->inbuf));
		syslog(LOG_DEBUG, "read ret:%d errno:%d.\n", err, errno);
		if (err < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			continue;

		if (err <= 0) {
			int e;

			if (err == 0)
				e = EBADF;
			else
				e = errno;

			pthread_mutex_lock(&priv->filter_lock);
			priv->err = e;
			if (e != EBADF && e != EFAULT) {
				if (priv->ph) {
					fuse_notify_poll(priv->ph);
					fuse_pollhandle_destroy(priv->ph);
					priv->ph = NULL;
				}
				pthread_mutex_unlock(&priv->filter_lock);
				continue;
			}
			pthread_mutex_unlock(&priv->filter_lock);
			break;
		}

		pthread_mutex_lock(&priv->filter_lock);
		priv->err = 0;
		priv->inbuf_len = err;
		stype = priv->stype;
		if (!priv->fs_priv->dmxraw && stype == SECTION_TYPE_NIT)
			convert_nit_sec(priv);
		else if (!priv->fs_priv->dmxraw && stype == SECTION_TYPE_SDT)
			convert_sdt_sec(priv);
		else if (!priv->fs_priv->dmxraw && stype == SECTION_TYPE_EIT)
			convert_eit_sec(priv);
		else
			direct_out(priv);
		pthread_mutex_unlock(&priv->filter_lock);
	}

	/* exiting */
	pthread_mutex_lock(&priv->filter_lock);
	if (!priv->err)
		priv->err = ENODEV;
	if (priv->ph) {
		fuse_notify_poll(priv->ph);
		fuse_pollhandle_destroy(priv->ph);
		priv->ph = NULL;
	}
	pthread_mutex_unlock(&priv->filter_lock);
	syslog(LOG_DEBUG, "filter loop exited.\n");
	pthread_cleanup_pop(0);
	return NULL;
}

/* called after successfull ioctl (mainly for DMX_SET_FILTER) */
int
secfilter_ioctl_hook(struct secfilter_priv *priv, int cmd, void *data)
{
	uint16_t pid = 0;
	char *p = data;

	pthread_mutex_lock(&priv->filter_lock);
	switch (cmd) {
	case DMX_SET_FILTER:
		pid = *((uint16_t *)p);
		switch (pid) {
		case PID_NIT:
			priv->stype = SECTION_TYPE_NIT;
			break;
		case PID_SDT:
			priv->stype = SECTION_TYPE_SDT;
			break;
		case PID_EITH:
			priv->stype = SECTION_TYPE_EIT;
			break;
		default:
			priv->stype = SECTION_TYPE_NONE;
		}
		break;
	case DMX_SET_PES_FILTER:
		priv->stype = SECTION_TYPE_PES;
		break;
	}
	/* flush the buffers */
	/* FIXME: invoke filter_loop here instead of this imperfect flushing */
	priv->inbuf_len = 0;
	priv->outbuf_head = priv->outbuf_tail = 0;
	priv->remaining_len = 0;
	priv->err = 0;
	pthread_mutex_unlock(&priv->filter_lock);
	syslog(LOG_DEBUG, "secfilter pid:%#04hx stype:%d\n", pid, priv->stype);
	return 0;
}

int
init_secfilter(struct secfilter_priv *priv)
{
	pthread_mutex_init(&priv->filter_lock, NULL);
	pthread_cond_init(&priv->buf_cond, NULL);
	pthread_mutex_init(&priv->cancel_lock, NULL);

	if (!priv->fs_priv->dmxraw) {
		priv->iconv_cd = iconv_open("UTF-16BE//TRANSLIT", "EUC-JISX0213");
		if (priv->iconv_cd == (iconv_t)-1) {
			syslog(LOG_INFO,
				"text conv. disabled as iconv_open() failed:%m\n");
			priv->fs_priv->dmxraw = 1;
		}
	}

	if (pthread_create(&priv->filter_thread, NULL, filter_loop, priv))
		return -errno;
	return 0;
}

void
release_secfilter(struct secfilter_priv *priv)
{
	pthread_cancel(priv->filter_thread);
	pthread_join(priv->filter_thread, NULL);

	/* TODO: replace _trylock with pthread_mutex_lock() and test */
	pthread_mutex_trylock(&priv->filter_lock);
	if (priv->ph) {
		priv->err = ENODEV;
		fuse_notify_poll(priv->ph);
		fuse_pollhandle_destroy(priv->ph);
		priv->ph = NULL;
	}
	pthread_mutex_unlock(&priv->filter_lock);
	syslog(LOG_DEBUG, "releasing demux device\n");

	if (!priv->fs_priv->dmxraw && priv->iconv_cd != (iconv_t)-1)
		iconv_close(priv->iconv_cd);
}


