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
 */

#ifndef MSC_CONNECTION_H
#define MSC_CONNECTION_H

#include <osmocore/linuxlist.h>
#include <osmocore/write_queue.h>
#include <osmocore/timer.h>

#include <osmocom/sccp/sccp.h>

struct bsc_data;
struct ss7_application;

struct msc_connection {
	/* management */
	struct llist_head entry;
	int nr;
	char *name;

	/* ip management */
	int dscp;
	char *ip;
	char *token;

	/* connection management */
	int msc_link_down;
	struct write_queue msc_connection;
	struct timer_list reconnect_timer;
	int first_contact;

	/* time to wait for first message from MSC */
	struct timer_list msc_timeout;
	int msc_time;

	/* timeouts for the msc connection */
	int ping_time;
	int pong_time;
	struct timer_list ping_timeout;
	struct timer_list pong_timeout;
	struct timer_list reset_timeout;

	/* mgcp messgaes */
	struct write_queue mgcp_agent;

	/* application pointer */
	struct llist_head sccp_connections;
	struct mtp_link_set *target_link;
	int forward_only;
	int reset_count;
};

/* msc related functions */
void msc_send_rlc(struct msc_connection *bsc, struct sccp_source_reference *src, struct sccp_source_reference *dest);
void msc_send_reset(struct msc_connection *bsc);
void msc_send_direct(struct msc_connection *bsc, struct msgb *msg);
void msc_close_connection(struct msc_connection *data);

struct msc_connection *msc_connection_create(struct bsc_data *bsc, int mgcp);
struct msc_connection *msc_connection_num(struct bsc_data *bsc, int num);
int msc_connection_start(struct msc_connection *msc);

/* MGCP */
void mgcp_forward(struct msc_connection *msc, const uint8_t *data, unsigned int length);

/* Called by the MSC Connection */
void msc_dispatch_sccp(struct msc_connection *msc, struct msgb *msg);


#endif
