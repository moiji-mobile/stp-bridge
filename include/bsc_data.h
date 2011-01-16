/* Everything related to the BSC connection */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#ifndef BSC_DATA_H
#define BSC_DATA_H

#include <osmocore/linuxlist.h>
#include <osmocore/select.h>
#include <osmocore/timer.h>
#include <osmocore/write_queue.h>

#include <osmocore/protocol/gsm_04_08.h>

#include <osmocom/sccp/sccp.h>


#include <netinet/in.h>
#include <arpa/inet.h>

struct bsc_data;
struct snmp_mtp_session;

/**
 * A link to the underlying MTP2 library or such
 */
struct link_data {
	union {
		struct {
			struct thread_notifier *notifier;
			struct llist_head mtp_queue;
			struct timer_list mtp_timeout;
		} c7;
		struct {
			struct write_queue write_queue;
			struct sockaddr_in remote;
			struct snmp_mtp_session *session;
			int reset_timeout;
		} udp;
	};

	int pcap_fd;
	struct bsc_data *bsc;
	struct mtp_link *the_link;

	struct timer_list link_activate;
	int forced_down;

	int (*start)(struct link_data *);
	int (*write)(struct link_data *, struct msgb *msg);
	int (*shutdown)(struct link_data *);
	int (*reset)(struct link_data *data);
	int (*clear_queue)(struct link_data *data);
};


struct bsc_data {
	/* MSC */
	char *msc_address;
	struct write_queue msc_connection;
	struct timer_list reconnect_timer;
	int first_contact;
	int msc_time;
	struct timer_list msc_timeout;
	int msc_ip_dscp;

	int ping_time;
	int pong_time;
	struct timer_list ping_timeout;
	struct timer_list pong_timeout;

	int msc_link_down;
	struct llist_head sccp_connections;
	struct timer_list reset_timeout;
	int reset_count;

	struct timer_list start_timer;

	int setup;

	struct link_data link;

	const char *token;

	/* mgcp messgaes */
	struct write_queue mgcp_agent;

	int dpc;
	int opc;
	int sccp_opc;
	int src_port;
	int udp_port;
	char *udp_ip;
	int once;

	/* the network header to use */
	int ni_ni;
	int ni_spare;

	/* LAC of the cell */
	struct gsm48_loc_area_id lai;
	uint16_t mcc;
	uint16_t mnc;
	uint16_t lac;

	int forward_only;
};

/* bsc related functions */
void release_bsc_resources(struct bsc_data *bsc);
void bsc_link_down(struct link_data *data);
void bsc_link_up(struct link_data *data);

/* msc related functions */
int msc_init(struct bsc_data *bsc, int mgcp);
void msc_send_rlc(struct bsc_data *bsc, struct sccp_source_reference *src, struct sccp_source_reference *dest);
void msc_send_reset(struct bsc_data *bsc);
void msc_send_msg(struct bsc_data *bsc, int rc, struct sccp_parse_result *, struct msgb *msg);
void msc_send_direct(struct bsc_data *bsc, struct msgb *msg);
void msc_clear_queue(struct bsc_data *data);
void msc_close_connection(struct bsc_data *data);

/* connection tracking and action */
void update_con_state(struct mtp_link *link, int rc, struct sccp_parse_result *result, struct msgb *msg, int from_msc, int sls);
unsigned int sls_for_src_ref(struct sccp_source_reference *ref);

/* c7 init */
int link_c7_init(struct link_data *data);

/* udp init */
int link_udp_init(struct link_data *data, int src_port, const char *dest_ip, int port);

/* MGCP */
void mgcp_forward(struct bsc_data *bsc, const uint8_t *data, unsigned int length);

#endif
