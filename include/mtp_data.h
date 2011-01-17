/*
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef mtp_data_h
#define mtp_data_h

#include <osmocore/msgb.h>
#include <osmocore/timer.h>
#include <osmocore/utils.h>

struct bsc_data;
struct mtp_link;

/* MTP Level3 timers */

/* Timers for SS7 */
#define MTP_T1		12, 0
#define MTP_T2		30, 0
#define START_DELAY	 8, 0

/**
 * The state of the mtp_link in terms of layer3 and upwards
 */
struct mtp_link_set {
	/* routing info.. */
	int dpc, opc, sccp_opc;
	int ni;
	int spare;

	/* internal state */
	/* the MTP1 link is up */
	int available;
	int running;
	int sccp_up;

	int last_sls;

	/* misc data */
	uint8_t test_ptrn[14];

	int sltm_pending;
	int sltm_once;
	int was_up;

	int slta_misses;
	struct timer_list t1_timer;
	struct timer_list t2_timer;

	struct timer_list delay_timer;

	struct llist_head links;
	struct mtp_link *slc[16];

	/* custom data */
	struct bsc_data *bsc;
};

/**
 * One physical link to somewhere. This is the base
 * with the interface used by the mtp_link_set. There
 * will be specific implementations for M2UA, UDP and
 * other transport means.
 */
struct mtp_link {
	struct llist_head entry;

	int pcap_fd;
	struct mtp_link_set *the_link;

	int available;

	struct timer_list link_activate;

	int (*start)(struct mtp_link *);
	int (*write)(struct mtp_link *, struct msgb *msg);
	int (*shutdown)(struct mtp_link *);
	int (*reset)(struct mtp_link *data);
	int (*clear_queue)(struct mtp_link *data);
};


struct mtp_link_set *mtp_link_set_alloc(void);
void mtp_link_set_stop(struct mtp_link_set *link);
void mtp_link_set_reset(struct mtp_link_set *link);
int mtp_link_set_data(struct mtp_link_set *link, struct msgb *msg);
int mtp_link_set_submit_sccp_data(struct mtp_link_set *link, int sls, const uint8_t *data, unsigned int length);
int mtp_link_set_submit_isup_data(struct mtp_link_set *link, int sls, const uint8_t *data, unsigned int length);

void mtp_link_set_init_slc(struct mtp_link_set *set);
void mtp_link_set_add_link(struct mtp_link_set *set, struct mtp_link *link);


/* one time init function */
void mtp_link_set_init(void);

/* to be implemented for MSU sending */
void mtp_link_set_submit(struct mtp_link *link, struct msgb *msg);
void mtp_link_set_forward_sccp(struct mtp_link_set *link, struct msgb *msg, int sls);
void mtp_link_set_forward_isup(struct mtp_link_set *link, struct msgb *msg, int sls);
void mtp_link_restart(struct mtp_link *link);
void mtp_link_set_sccp_down(struct mtp_link_set *link);

#endif
