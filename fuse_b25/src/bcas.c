/*
 * bcas.c: BCAS card I/O for FUSE b25
 * Copyright 2009 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "bcas.h"

/* for htonll(), ntohll() */
#include "demulti2.h"

#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef NO_SYSLOG
#define syslog(a, args...) fprintf(stderr, args...)
#endif

#define CARD_SW1_OK 0x90
#define CARD_SW2_OK 0x00

#define CARD_TYPE_GENERAL 0x01

#define SYS_MNG_ID_B14 0x0301
#define SYS_MNG_ID_B15 0x0201

#define CA_SYSTEM_ID_ARIB 0x0005
#define CA_SYSTEM_ID_ARIB_B 0x000A

#define BCAS_MULTI2_ROUND 4

#define CARD_RETCODE_OK 0x2100
#define CARD_RETCODE_GD_TIER 0x0800
#define CARD_RETCODE_GD_PREPPV 0x0400
#define CARD_RETCODE_GD_POSTPPV 0x0200
#define CARD_RETCODE_PV_PREPPV 0x4480
#define CARD_RETCODE_PV_POSTPPV 0x4280

#define CARD_DIR_PWRON_CTL (1 << 0)
#define CARD_DIR_RINGING_DATE (1 << 1)
#define CARD_DIR_DEL_PASSWD (1 << 2)
#define CARD_DIR_RING (1 << 3)
#define CARD_DIR_RETRY_OVER (1 << 5)
#define CARD_DIR_HANGUP_LINE (1 << 6)
#define CARD_DIR_INIT_PARAM (1 << 7)
#define CARD_DIR_CARD_ID (1 << 8)
#define CARD_DIR_CHANGE_CARD (1 << 9)


/* example ATR of BCAS. FIXME: byte[2],[4],[8-9],[11-12] may vary */
static const BYTE bcas_atr[] = {
  0x3B, 0xF0, 0x12, 0x00, 0xFF, 0x91, 0x81,
  0xB1, 0x7C, 0x45, 0x1F, 0x03, 0x99
};

static const DWORD BCAS_ATR_LEN = sizeof (bcas_atr);

static char *
get_card (SCARDCONTEXT cxt, SCARDHANDLE * h, char * iccname)
{
  LONG ret;
  DWORD len, protocol;
  char *p, *readers;
  DWORD nlen, alen;
  DWORD state;
  BYTE atr[MAX_ATR_SIZE];

  ret = SCardListReaders (cxt, NULL, NULL, &len);
  if (ret != SCARD_S_SUCCESS) {
    syslog (LOG_NOTICE, "Failed to get the length of the card list: %s\n",
        pcsc_stringify_error (ret));
    return NULL;
  }

  readers = (char *) malloc (len);
  if (!readers) {
    syslog (LOG_NOTICE, "Failed to alloc memory for the card list.\n");
    return NULL;
  }

  ret = SCardListReaders (cxt, NULL, readers, &len);
  if (ret != SCARD_S_SUCCESS) {
    syslog (LOG_NOTICE, "Failed to get the card list: %s\n",
        pcsc_stringify_error (ret));
    free (readers);
    return NULL;
  }

  for (p = readers; *p; p += strlen (p) + 1) {
    if (iccname &&
        (strlen (p) != strlen (iccname) || strncmp (p, iccname, strlen (p))))
      continue;
    ret = SCardConnect (cxt, p, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
        h, &protocol);
    if (ret != SCARD_S_SUCCESS) {
      syslog (LOG_INFO, "Failed to connect the card [%s]/%s.\n",
          p, pcsc_stringify_error (ret));
      continue;
    }
    alen = sizeof (atr);
    ret = SCardStatus (*h, NULL, &nlen, &state, &protocol, atr, &alen);
    if (ret == SCARD_S_SUCCESS && (state & SCARD_PRESENT) &&
        alen == BCAS_ATR_LEN &&
        atr[0] == bcas_atr[0] && atr[1] == bcas_atr[1]) {
      iccname = strdup (p);
      free (readers);
      return iccname;
    }
  }
  free (readers);
  return NULL;
}


/* init card and set some ID infos */
static int
bcas_card_setup (struct bcas * card)
{
  LONG ret;
  DWORD protocol, rlen;
  SCARD_IO_REQUEST rpci;
  uint8_t rspbuf[BCAS_MAX_MSG_LEN];

  char *name;
  uint retry;
  uint16_t cas_id;
  int i;

  static const struct timespec wt1 = {1, 0};
  static const uint8_t init_cmd[] = { 0x90, 0x30, 0x00, 0x00, 0x00 };
  static const uint8_t cardinfo_cmd[] = { 0x90, 0x32, 0x00, 0x00, 0x00 };

//  card->status = CARD_S_NG;

//  SCardSetTimeout (info->cxt, 3);

  name = get_card (card->cxt, &card->hcard, card->iccname);
  if (!name) {
    syslog (LOG_NOTICE, "Failed to find an available BCAS card.\n");
    goto bailout;
  }
  free(name);

  retry = 0;
  while (retry < 3) {
    memcpy (&rpci, SCARD_PCI_T1, sizeof (rpci));
    rlen = sizeof (rspbuf);
    ret = SCardTransmit (card->hcard, SCARD_PCI_T1, init_cmd, sizeof (init_cmd),
        &rpci, rspbuf, &rlen);
    if (ret == SCARD_W_RESET_CARD) {
      ret = SCardReconnect (card->hcard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
          SCARD_LEAVE_CARD, &protocol);
    }
    if (ret == SCARD_S_SUCCESS)
      break;
    retry++;
    nanosleep (&wt1, NULL);
  }
  if (retry == 3 || rlen < 59) {
    syslog (LOG_INFO, "Failed to initialize the card.\n");
    goto bailout;
  }
  cas_id = rspbuf[6] << 8 | rspbuf[7];
  if (rspbuf[rlen - 2] != CARD_SW1_OK || rspbuf[rlen - 1] != CARD_SW2_OK ||
      rspbuf[1] < 55 || (rspbuf[4] << 8 | rspbuf[5]) != CARD_RETCODE_OK ||
      (cas_id != CA_SYSTEM_ID_ARIB && cas_id != CA_SYSTEM_ID_ARIB_B) ||
      rspbuf[14] != CARD_TYPE_GENERAL) {
    syslog (LOG_INFO, "Got bad response for the card init command.\n");
    goto bailout;
  }
  card->cas_id = cas_id;

  /* omit checking the card directions(rspbuf[2-3]) and retcode(rspbuf[4-5]) */
  /* omit checking if sys_management_id[](rspbuf[57..]) includes the valid ID */

  /* copy the initial data */
  for (i = 0; i < 8; i++) {
    card->param.k_sys[i] = ntohl (*(u32 *) (rspbuf + 16 + i * 4));
  }
  card->param.cbc_init.whole = ntohll (*((u64 *) & rspbuf[48]));

  /* redundant. overwritten very soon by the next command */
  memcpy (&card->id[0][2], &rspbuf[8], 6);
  card->num_id = 1;

  /* get the card info */
  retry = 0;
  while (retry < 3) {
    memcpy (&rpci, SCARD_PCI_T1, sizeof (rpci));
    rlen = sizeof (rspbuf);
    ret = SCardTransmit (card->hcard, SCARD_PCI_T1,
        cardinfo_cmd, sizeof (cardinfo_cmd), &rpci, rspbuf, &rlen);
    if (ret == SCARD_W_RESET_CARD) {
      ret = SCardReconnect (card->hcard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
          SCARD_LEAVE_CARD, &protocol);
    }
    if (ret == SCARD_S_SUCCESS)
      break;
    retry++;
    nanosleep (&wt1, NULL);
  }
  if (retry == 3 || rlen < 19) {
    syslog (LOG_INFO, "Failed to get info from the the card.\n");
    goto bailout;
  }

  if (rspbuf[rlen - 2] != CARD_SW1_OK || rspbuf[rlen - 1] != CARD_SW2_OK ||
      rspbuf[1] < 15 || (rspbuf[4] << 8 | rspbuf[5]) != CARD_RETCODE_OK ||
      rspbuf[6] < 1 || rspbuf[6] > 8) {
    syslog (LOG_INFO, "Got bad response for the card info command.\n");
    goto bailout;
  }

  /* copy the card IDs */
  card->num_id = rspbuf[6];
  memcpy (card->id, &rspbuf[7], 10 * rspbuf[6]);
  card->status = CARD_S_OK;
  syslog (LOG_INFO, "BCAS card init succeeded.\n");
  return 0;

bailout:
  syslog (LOG_NOTICE, "BCAS card not available.\n");
  return -1;
}


static void
do_io_loop(struct bcas *card)
{
  LONG ret;
  DWORD protocol, rlen;
  SCARD_IO_REQUEST rpci;
  static const struct timespec wt1 = {1, 0};

  uint retry = 0;
  uint8_t cmdbuf[BCAS_MAX_MSG_LEN], rspbuf[BCAS_MAX_MSG_LEN];
  int clen;
  void (*cmd_cb)(struct bcas *card, void *data, uint8_t *rbuf, size_t rlen);
  void *cmd_arg;

  while (1) {
    pthread_mutex_lock (&card->lock);
    while ((clen = card->cmd_len) == 0)
      pthread_cond_wait (&card->cond, &card->lock);

    /* copy the args */
    if (clen > 0 && clen <= BCAS_MAX_MSG_LEN)
      memcpy (cmdbuf, card->cmdbuf, clen);
    cmd_cb = card->cmd_cb;
    cmd_arg = card->cmd_arg;
    card->cmd_len = 0;
    pthread_mutex_unlock (&card->lock);

    if (clen < 0 || card->status == CARD_S_NG)
      break;

    if (clen > BCAS_MAX_MSG_LEN) {
      syslog (LOG_INFO, "Too long CARD command (%dB).\n", clen); 
      goto failed;
    }

    memcpy (&rpci, SCARD_PCI_T1, sizeof (rpci));
    rlen = sizeof (rspbuf);
    ret = SCardTransmit (card->hcard, SCARD_PCI_T1, cmdbuf, clen,
			 &rpci, rspbuf, &rlen);
    if (ret == SCARD_W_RESET_CARD) {
      syslog (LOG_INFO, "resetting the card.\n"); 
      ret = SCardReconnect (card->hcard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
          SCARD_LEAVE_CARD, &protocol);
    }

    if (ret != SCARD_S_SUCCESS) {
      if (++retry >= 3) {
        syslog (LOG_NOTICE, "Failed to retry card command %d times.\n", retry);
        goto bailout;
      }
      SCardDisconnect (card->hcard, SCARD_RESET_CARD);
      nanosleep(&wt1, NULL);
      ret = SCardReconnect (card->hcard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
           SCARD_RESET_CARD, &protocol);
      if (ret != SCARD_S_SUCCESS) {
        syslog (LOG_INFO, "Failed to reset the card.\n");
        goto bailout;
      } else {
        goto failed;
      }
    }
    retry = 0;

    /* check if failed and update the status */
    if (rlen < 6 ||
        rspbuf[rlen - 2] != CARD_SW1_OK || rspbuf[rlen - 1] != CARD_SW2_OK) {
      syslog (LOG_INFO,
        "Got a bad response from the card. len:%ld, SW1/2:[0x%02X%02X].\n",
        rlen, rspbuf[rlen - 2], rspbuf[rlen - 1]);
      goto bailout;
    }

    /* currently, we ignore the directions from IC cards. just print it. */
    if (rspbuf[2] || rspbuf[3]) {
      syslog (LOG_WARNING, "Directions from the card.[0x%04x].\n",
        (uint16_t) (rspbuf[2] << 8 | rspbuf[3]));
    }
    /* call the callback func. */
    if (cmd_cb)
      cmd_cb (card, cmd_arg, rspbuf, rlen);

    continue;

failed:
    pthread_mutex_lock (&card->lock);
    if (cmd_arg) {
      struct demulti2_key_info *kinfo = cmd_arg;
      kinfo->status = CMD_S_FAILED;
    }
    pthread_mutex_unlock (&card->lock);
    continue;

bailout:
    pthread_mutex_lock (&card->lock);
    if (cmd_arg) {
      struct demulti2_key_info *kinfo = cmd_arg;
      kinfo->status = CMD_S_FAILED;
    }
    card->status = CARD_S_NG;
    pthread_mutex_unlock (&card->lock);
    break;
  }
  return;
}

#define MAX_ERROR_RETRY 5

static void
bcas_ecm_cb (struct bcas *card, void *data, uint8_t *rbuf, size_t rlen)
{
  struct demulti2_key_info *kinfo = data;
  uint16_t retcode;
  uint64_t k_odd, k_even;

  syslog (LOG_DEBUG, "Got an ECM response.\n");

#define ECM_RSP_UNIT_SIZE 21
  if (rlen < ECM_RSP_UNIT_SIZE + 4 || rbuf[1] != ECM_RSP_UNIT_SIZE) {
    syslog (LOG_INFO,
        "Bad ECM response, len:%ld, unit-len:%d.\n", rlen, rbuf[1]);
    goto failed;
  }
  retcode = rbuf[4] << 8 | rbuf[5];
  if (retcode != CARD_RETCODE_GD_TIER &&
      retcode != CARD_RETCODE_GD_PREPPV &&
      retcode != CARD_RETCODE_GD_POSTPPV &&
      retcode != CARD_RETCODE_PV_PREPPV && retcode != CARD_RETCODE_PV_POSTPPV) {
    syslog (LOG_NOTICE,
        "Bad ret code[0x%04x] in a ECM response.\n", retcode);
    goto failed;
  }

  k_odd = ntohll (*(uint64_t *) & rbuf[6]);
  k_even = ntohll (*(uint64_t *) & rbuf[14]);

  pthread_mutex_lock (&card->lock);
  card->errors = 0;
  if (k_odd != kinfo->k_scr[0].whole) {
    syslog (LOG_DEBUG, "ECM k_odd updated.\n");
    kinfo->k_scr[0].whole = k_odd;
    core_schedule (kinfo->wrk[0], card->param.k_sys, &kinfo->k_scr[0].sub);
  }
  if (k_even != kinfo->k_scr[1].whole) {
    syslog (LOG_DEBUG, "ECM k_even updated.\n");
    kinfo->k_scr[1].whole = k_even;
    core_schedule (kinfo->wrk[1], card->param.k_sys, &kinfo->k_scr[1].sub);
  }
  kinfo->status = CMD_S_OK;
  pthread_mutex_unlock (&card->lock);

  return;

failed:
  pthread_mutex_lock (&card->lock);
  kinfo->status = CMD_S_FAILED;
  if (++card->errors > MAX_ERROR_RETRY) {
    syslog (LOG_NOTICE, "Card I/O failed too many times.\n");
    card->status = CARD_S_NG;
  }
  pthread_mutex_unlock (&card->lock);
  return;
}


/*
 * exported funcs
 */

/* send an ECM command to the BCAS card. */
void
bcas_set_ecm(uint8_t *buf, int len, struct demulti2_key_info *kinfo,
		   struct bcas *card)
{
	/* ECM cmd: head +  Lc:n, DATA:ecm_data[n], Le:00 */
	/*     (len = 6+n) */
	static const uint8_t ecm_cmd_head[] = {0x90, 0x34, 0x00, 0x00};
	uint8_t *cmdbuf;

	pthread_mutex_lock(&card->lock);
	if (card->status != CARD_S_OK)
		goto bailout;

	if (card->cmd_len != 0)
		goto bailout;

	card->cmd_cb = bcas_ecm_cb;
	card->cmd_arg = kinfo;

	cmdbuf = card->cmdbuf;
	memcpy(cmdbuf, ecm_cmd_head, sizeof(ecm_cmd_head));
	cmdbuf[sizeof(ecm_cmd_head)] = len;
	memcpy(cmdbuf + sizeof(ecm_cmd_head) + 1, buf, len);
	cmdbuf[sizeof(ecm_cmd_head) + 1 + len] = 0x00;

	card->cmd_len = sizeof(ecm_cmd_head) + 2 + len;

	if (kinfo->status == CMD_S_OK)
		kinfo->status = CMD_S_UPDATING;
	else
		kinfo->status = CMD_S_QUERYING;

	pthread_cond_broadcast(&card->cond);
	pthread_mutex_unlock(&card->lock);
	syslog(LOG_DEBUG, "sent an ECM to the card.(len:%d)\n", len);
	return;

bailout:
	kinfo->status = CMD_S_FAILED;
	if (++card->errors > MAX_ERROR_RETRY) {
		syslog (LOG_NOTICE, "Card I/O failed too many times.\n");
		card->status = CARD_S_NG;
	}
	pthread_mutex_unlock(&card->lock);
	syslog(LOG_INFO, "dropped an ECM due to the failed/slow card.\n");
	return;
}


/* TODO: test EMM processing */
void
bcas_set_emm(uint8_t *buf, struct bcas *card)
{
	/* EMM cmd: head +  Lc:n, DATA:emm_data[n], Le:00 */
	/*     (len = 6+n) */
	static uint8_t emm_cmd_head[] = {0x90, 0x36, 0x00, 0x00};
	uint8_t *cmdbuf;
	int len;

	pthread_mutex_lock(&card->lock);
	if (card->status != CARD_S_OK)
		goto bailout;

	if (card->cmd_len != 0)
		goto bailout;

	len = buf[6] + 7;
	card->cmd_cb = NULL;
	card->cmd_arg = NULL;

	cmdbuf = card->cmdbuf;
	memcpy(cmdbuf, emm_cmd_head, sizeof(emm_cmd_head));
	cmdbuf[sizeof(emm_cmd_head)] = len;
	memcpy(cmdbuf + sizeof(emm_cmd_head) + 1, buf, len);
	cmdbuf[sizeof(emm_cmd_head) + 1 + len] = 0x00;

	card->cmd_len = sizeof(emm_cmd_head) + 2 + len;

	pthread_cond_broadcast(&card->cond);
	pthread_mutex_unlock(&card->lock);
	syslog(LOG_INFO, "sent an EMM to the card.(len:%d)\n", len);
	return;

bailout:
	if (++card->errors > MAX_ERROR_RETRY) {
		syslog (LOG_NOTICE, "Card I/O failed too many times.\n");
		card->status = CARD_S_NG;
	}
	pthread_mutex_unlock(&card->lock);
	syslog(LOG_WARNING, "dropped an EMM due to the failed/slow card.\n");
	return;
}


#define BCAS_RETRY_WAIT 5
/* thread func which inits & processes card I/Os */
/* if failed, wait & retry */
void *
bcas_card_io(void *arg)
{
	struct bcas *card = arg;
	struct timespec wt = {BCAS_RETRY_WAIT, 0};
	int stop;
	LONG ret;
	int res;

	pthread_mutex_lock(&card->lock);
	while (1) {
		/* assert(card->status == CARD_S_NG) */
		if (card->stop)
			break;
		card->status = CARD_S_NG;
		ret = SCardEstablishContext(SCARD_SCOPE_SYSTEM,
					    NULL, NULL, &card->cxt);
		if (ret != SCARD_S_SUCCESS) {
			syslog(LOG_NOTICE, "Can't connect to pcscd:%s.\n",
				pcsc_stringify_error (ret));
			goto retry;
  		}

		res = bcas_card_setup(card);
		if (res != 0)
			goto retry;
		/* assert(card->status == CARD_S_OK) */
		pthread_mutex_unlock(&card->lock);
		do_io_loop(card);
		pthread_mutex_lock(&card->lock);

retry:
		card->status == CARD_S_NG;
		if (card->hcard)
			SCardDisconnect (card->hcard, SCARD_RESET_CARD);
		card->hcard = 0;
		SCardReleaseContext (card->cxt);
		if (card->stop == 0)
			pthread_cond_timedwait(&card->cond, &card->lock, &wt);
	}

	pthread_mutex_unlock(&card->lock);
	return;
}

int
bcas_init(struct bcas *card)
{
	pthread_mutex_init (&card->lock, NULL);
	pthread_cond_init (&card->cond, NULL);
	card->param.round = BCAS_MULTI2_ROUND;
	// card->stop = 0; /* "card" is calloced */
	return pthread_create(&card->thread, NULL, bcas_card_io, card);
}

void
bcas_destroy(struct bcas *card)
{
	struct timespec wt1 = {0,300000000};

	pthread_mutex_lock (&card->lock);
	card->stop = 1;
	card->cmd_len = -1; // tells the thread to quit
	pthread_cond_broadcast(&card->cond);
	pthread_mutex_unlock(&card->lock);
	//pthread_cancel(card->thread);
	pthread_join(card->thread, NULL);
	//pthread_detach(card->thread);
	nanosleep(&wt1, NULL);

	if (card->hcard)
		SCardDisconnect (card->hcard, SCARD_RESET_CARD);
	SCardReleaseContext (card->cxt);
	return;
}

