/* Everything related to linksets */
/*
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
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

#ifndef linkset_h
#define linkset_h

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

#include <stdint.h>

struct msgb;

/**
 * The state of the mtp_link in terms of layer3 and upwards
 */
struct mtp_link_set {
	struct llist_head entry;
	int nr;
	char *name;

	/*
	 * Callbacks for the SS7 application
	 */
	void (*on_down) (struct mtp_link_set *set);
	void (*on_up) (struct mtp_link_set *set);
	void (*on_sccp) (struct mtp_link_set *set, struct msgb *msg, int sls);
	void (*on_isup) (struct mtp_link_set *set, struct msgb *msg, int sls);


	/**
	 * Routing is very limited. We can only forward to one
	 * other STP/Endpoint. For ISUP and SCCP we can statically
	 * send it to another destination. We need to follow Q.704
	 * more properly here.
	 * DPC/OPC are the ones for the linkset,
	 * sccp_dpc/isup_dpc are where we will send SCCP/ISUP messages
	 * sccp_opc/isup_opc are what we announce in the TFP
	 */
	int dpc, opc;
	int sccp_dpc, isup_dpc;
	int sccp_opc, isup_opc;
	int ni;
	int spare;


	/* internal state */
	/* the MTP1 link is up */
	int available;
	int running;
	int sccp_up;
	int linkset_up;

	int last_sls;

	struct llist_head links;
	int nr_links;
	struct mtp_link *slc[16];
	int sltm_once;

	/* ssn map */
	int supported_ssn[256];

	int pcap_fd;

	/* special handling */
	int pass_all_isup;

	/* statistics */
	struct rate_ctr_group *ctrg;

	/* statistics for routing */
	int timeout_t18;
	int timeout_t20;
	struct osmo_timer_list T18;
	struct osmo_timer_list T20;

	/* custom data */
	struct bsc_data *bsc;
	struct ss7_application *app;
};

void mtp_link_set_stop(struct mtp_link_set *set);
void mtp_link_set_reset(struct mtp_link_set *set);
int mtp_link_set_data(struct mtp_link *link, struct msgb *msg);
int mtp_link_handle_data(struct mtp_link *link, struct msgb *msg);
int mtp_link_set_submit_sccp_data(struct mtp_link_set *set, int sls, const uint8_t *data, unsigned int length);
int mtp_link_set_submit_isup_data(struct mtp_link_set *set, int sls, const uint8_t *data, unsigned int length);

void mtp_link_set_init_slc(struct mtp_link_set *set);

/* link management */
struct mtp_link_set *mtp_link_set_alloc(struct bsc_data *bsc);
struct mtp_link_set *mtp_link_set_num(struct bsc_data *bsc, int num);

/* to be implemented for MSU sending */
int mtp_link_set_send(struct mtp_link_set *set, struct msgb *msg);

/* internal routines */
struct msgb *mtp_msg_alloc(struct mtp_link_set *set);


#endif
