/*
 * FUSE b25: MULTI2 de-scrambler for /dev/dvb/adapterN/dvr0
 * Copyright 2009 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include <config.h>

#define FUSE_USE_VERSION 28

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <inttypes.h>
#include <pthread.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "bcas.h"
#include "stream.h"

#if NO_SYSLOG
#define syslog(a, args...) fprintf(stderr, args...)
#endif

struct options b25_priv;

static struct fuse_opt b25_opts[] =
{
	{"--card %s", offsetof(struct options, card_name), 0},
	{"--noemm", offsetof(struct options, emm), 0},
	{"--conv", offsetof(struct options, conv), 1},
	{"--eit", offsetof(struct options, eit), 1},
};

/* file system operations */
static int
b25_getattr(const char *path, struct stat *stbuf)
{
	if(strcmp(path, "/") != 0)
		return -ENOENT;

	if (fuse_interrupted())
		return -EINTR;

 	memset(stbuf, 0, sizeof(struct stat));
	errno = 0;
	stat(b25_priv.dvr_name, stbuf);
	stbuf->st_mode &= ~S_IFCHR;
	stbuf->st_mode |= S_IFREG;
	return 0;//-errno;
}

static int
b25_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
	struct stream_priv *stream;
	int res;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	if (fuse_interrupted())
		return -EINTR;

	if((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;
	fi->flags &= ~(O_CREAT | O_EXCL | O_NONBLOCK | O_NDELAY);
	/*
	 * FIXME: if vfs layer does not check the permission,
	 * check here with fuse_get_context()->uid,gid
	 */

	syslog(LOG_DEBUG, "dvr0 open flags:%#x\n", fi->flags);

	fd = open(b25_priv.dvr_name, fi->flags);
	if (fd < 0) {
		res = -errno;
		syslog(LOG_INFO, "failed to open dvr0 device: %m\n");
		return res;
	}

	stream = calloc(1, sizeof(struct stream_priv));
	if (stream == NULL) {
		syslog(LOG_NOTICE, "failed to allocate mem for stream.\n");
		return -ENOMEM;
	}

	stream->fd = fd;
	stream->fs_priv = &b25_priv;
	res = init_stream(stream);
	if (res != 0) {
		close(stream->fd);
		free(stream);
		return res;
	}

	fi->fh = (int64_t)stream;
	fi->direct_io = 1;
	fi->nonseekable = 1;
	return 0;
}

static int
b25_release(const char *path, struct fuse_file_info *fi)
{
	struct stream_priv *stream;

	stream = (struct stream_priv *)fi->fh;
	release_stream(stream);
	close(stream->fd);
	free(stream);
	return 0;
}

static int
b25_read(const char *path, char *buf, size_t size, off_t offset,
	 struct fuse_file_info *fi)
{
	struct stream_priv *stream;
	struct timeval now;
	struct timespec timeout;
	int len;
	int l;
	int ret;

	(void)offset;

	if (fuse_interrupted())
		return -EINTR;

	stream = (struct stream_priv *)fi->fh;
	pthread_mutex_lock(&stream->buf_lock);
	while (stream->err == 0 &&
	       stream->outbuf_head == stream->outbuf_tail) {
		gettimeofday(&now, NULL);
		timeout.tv_sec = now.tv_sec + 5;
		timeout.tv_nsec = now.tv_usec * 1000;
		ret = pthread_cond_timedwait(&stream->buf_cond,
					   &stream->buf_lock, &timeout);
		if (ret == EINTR || fuse_interrupted()) {
			pthread_mutex_unlock(&stream->buf_lock);
			return -EINTR;
		}
	}

	if (stream->err != 0) {
		len = -stream->err;
		syslog(LOG_DEBUG, "failed to read from dvr0 device.\n");
		goto done;
	}

	if (stream->outbuf_head > stream->outbuf_tail) {
		len = sizeof(stream->outbuf) - stream->outbuf_head;
		if (size < len)
			len = size;
		memcpy(buf, stream->outbuf + stream->outbuf_head, len);
		size -= len;
		stream->outbuf_head += len;
		if (stream->outbuf_head == sizeof(stream->outbuf))
			stream->outbuf_head = 0;
		if (size > 0) {
			if (size > stream->outbuf_tail)
				size = stream->outbuf_tail;
			memcpy(buf + len, stream->outbuf, size);
			stream->outbuf_head = size;
			len += size;
		}
	} else {
		len = stream->outbuf_tail - stream->outbuf_head;
		if (size < len)
			len = size;
		memcpy(buf, stream->outbuf + stream->outbuf_head, len);
		stream->outbuf_head += len;
	}

done:
	pthread_mutex_unlock(&stream->buf_lock);
	return len;
}

static int
b25_ioctl(const char *path, int cmd, void *arg,
	  struct fuse_file_info *fi, unsigned int flags, void *data)
{
	(void)arg;
	(void)fi;
	(void)flags;
	(void)data;

	if (fuse_interrupted())
		return -EINTR;

/* copied from linux/dvb/dmx.h */
#define DMX_SET_BUFFER_SIZE      _IO('o', 45)
	if (cmd != DMX_SET_BUFFER_SIZE)
		return -EINVAL;

	/* just ignore the ioctl */
	return 0;
}

static int
b25_poll(const char *path, struct fuse_file_info *fi,
	 struct fuse_pollhandle *ph, unsigned *reventsp)
{
	struct stream_priv *stream;
	int res;

	(void)path;

	if (fuse_interrupted())
		return -EINTR;

	stream = (struct stream_priv *)fi->fh;

	*reventsp = 0;
	pthread_mutex_lock(&stream->buf_lock);
	if (ph != NULL) {
		if (stream->ph != NULL)
			fuse_pollhandle_destroy(stream->ph);
		stream->ph = ph;
	}

	if (stream->err != 0)
		*reventsp = POLLERR;
	else if (stream->outbuf_head != stream->outbuf_tail)
		*reventsp = POLLIN;

	pthread_mutex_unlock(&stream->buf_lock);
	return 0;
}

static void *
b25_init(struct fuse_conn_info *conn)
{
	int res;

	(void)conn;

	b25_priv.card.iccname = b25_priv.card_name;
	res = bcas_init(&b25_priv.card);
	if (res != 0) {
		syslog(LOG_NOTICE, "failed to invoke the card I/O thread.\n");
		fuse_exit(fuse_get_context()->fuse);
		return NULL;
	}
	return &b25_priv.card;
}

static void
b25_destroy(void *priv)
{
	struct bcas *card;

	card = &b25_priv.card;
	if (card != NULL)
		bcas_destroy(card);
}

static struct fuse_operations b25_ops = {
	.getattr = b25_getattr,
	.open = b25_open,
	.release = b25_release,
	.read = b25_read,
	.init = b25_init,
	.destroy = b25_destroy,
	.ioctl = b25_ioctl,
	.poll = b25_poll,
};

int
main(int argc, char **argv)
{
	struct fuse *fuse;
	char *mountpoint;
	int multithreaded;
	int res;
	unsigned int adapter, dvr;
	unsigned int t_adap, t_dvr;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	openlog("FUSE_b25", LOG_PID | LOG_PERROR, LOG_LOCAL7);

	memset(&b25_priv, 0, sizeof(b25_priv));
	b25_priv.emm = 1;
	b25_priv.conv = 0;
	res = fuse_opt_parse(&args, &b25_priv, b25_opts, NULL);
	if (res == -1) {
		syslog(LOG_NOTICE, "failed to parse options: %m\n");
		return 1;
	}
	res = fuse_opt_add_arg(&args, "-odirect_io");
	res += fuse_opt_add_arg(&args, "-odefault_permissions");
	if (res < 0) {
		syslog(LOG_NOTICE, "failed to add \"direct_io\"/"
			"\"default_permissions\" options: %m\n");
		return 1;
	}

	/* copied from fuse_main_real() */
	fuse = fuse_setup(args.argc, args.argv, &b25_ops, sizeof(b25_ops),
			  &mountpoint, &multithreaded, NULL);
	fuse_opt_free_args(&args);
	if (fuse == NULL) {
		syslog(LOG_NOTICE, "failed to setup fuse: %m\n");
		return 1;
	}

	res = sscanf(mountpoint, "/dev/dvb/adapter%u/dvr%u", &adapter, &dvr);
	if (res != 2) {
		syslog(LOG_NOTICE, "invalid mount point: \"%s\"\n", mountpoint);
		return 1;
	}

	res = snprintf(b25_priv.dvr_name, sizeof(b25_priv.dvr_name),
		      "/dev/dvb/adapter%u/dvr_b25", adapter);
	if (res < 0 
#if HAVE_EACCESS
	    || eaccess(b25_priv.dvr_name, R_OK) != 0
#endif
	   ) {
		syslog(LOG_NOTICE, "can't access the target DVR0 device:[%s]\n", b25_priv.dvr_name);
		return 1;
	}

	/* main loop */
	if (multithreaded)
		res = fuse_loop_mt(fuse);
	else
		res = fuse_loop(fuse);

	if (res == -1)
		syslog(LOG_NOTICE, "failed in fuse_loop: %m\n");

finish:
	fuse_teardown(fuse, mountpoint);
	closelog();
	return res;
}
