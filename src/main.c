/* Bloated main routine, refactor */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <mtp_data.h>
#include <mtp_pcap.h>
#include <thread.h>
#include <bss_patch.h>
#include <bssap_sccp.h>
#include <bsc_data.h>
#include <snmp_mtp.h>
#include <cellmgr_debug.h>

#include <osmocore/talloc.h>
#include <osmocore/protocol/gsm_08_08.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <netdb.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>

static struct log_target *stderr_target;
static int dpc = 1;
static int opc = 0;

static char *config = "cellmgr_ng.cfg";
static int udp_port = 3456;
static char *udp_ip = NULL;
static int src_port = 1313;
static int once = 0;
static int flood = 0;
static struct timer_list flood_timer;

static struct vty_app_info vty_info = {
	.name 		= "Cellmgr-ng",
	.version	= "0.0.1",
	.go_parent_cb	= NULL,
};

/*
 * One SCCP connection.
 * Use for connection tracking and fixups...
 */
struct active_sccp_con {
	struct llist_head entry;

	struct sccp_source_reference src_ref;
	struct sccp_source_reference dst_ref;

	int has_dst_ref;

	/* fixup stuff */

	/* We get a RLSD from the MSC and need to send a RLC */
	int released_from_msc;

	/* timeout for waiting for the RLC */
	struct timer_list rlc_timeout;

	/* how often did we send a RLSD this */
	unsigned int rls_tries;

	/* sls id */
	int sls;
};

static struct bsc_data bsc;

static void send_reset_ack(struct mtp_link *link, int sls);
static void bsc_resources_released(struct bsc_data *bsc);
static void handle_local_sccp(struct mtp_link *link, struct msgb *inp, struct sccp_parse_result *res, int sls);
static void clear_connections(struct bsc_data *bsc);
static void send_local_rlsd(struct mtp_link *link, struct sccp_parse_result *res);
static void start_flood();
static void cell_vty_init(void);

int link_c7_init(struct link_data *data) __attribute__((__weak__));

int link_c7_init(struct link_data *data)
{
	return -1;
}

/* send a RSIP to the MGCP GW */
static void mgcp_reset(struct bsc_data *bsc)
{
        static const char mgcp_reset[] = {
            "RSIP 1 13@mgw MGCP 1.0\r\n"
        };

	mgcp_forward(bsc, (const uint8_t *) mgcp_reset, strlen(mgcp_reset));
}

/*
 * methods called from the MTP Level3 part
 */
void mtp_link_submit(struct mtp_link *link, struct msgb *msg)
{
	bsc.link.write(&bsc.link, msg);
}

void mtp_link_restart(struct mtp_link *link)
{
	LOGP(DINP, LOGL_ERROR, "Need to restart the SS7 link.\n");
	bsc.link.reset(&bsc.link);
}

void mtp_link_sccp_down(struct mtp_link *link)
{
	msc_clear_queue(&bsc);
}

void mtp_link_forward_sccp(struct mtp_link *link, struct msgb *_msg, int sls)
{
	int rc;
	struct sccp_parse_result result;

	rc = bss_patch_filter_msg(_msg, &result);
	if (rc == BSS_FILTER_RESET) {
		LOGP(DMSC, LOGL_NOTICE, "Filtering BSS Reset from the BSC\n");
		msc_clear_queue(&bsc);
		mgcp_reset(&bsc);
		send_reset_ack(link, sls);
		return;
	}

	/* special responder */
	if (bsc.closing) {
		if (rc == BSS_FILTER_RESET_ACK && bsc.reset_count > 0) {
			LOGP(DMSC, LOGL_ERROR, "Received reset ack for closing.\n");
			clear_connections(&bsc);
			bsc_resources_released(&bsc);
			return;
		}

		if (rc != 0 && rc != BSS_FILTER_RLSD && rc != BSS_FILTER_RLC) {
			LOGP(DMSC, LOGL_ERROR, "Ignoring unparsable msg during closedown.\n");
			return;
		}

		return handle_local_sccp(link, _msg, &result, sls);
	}

	/* update the connection state */
	update_con_state(rc, &result, _msg, 0, sls);

	if (rc == BSS_FILTER_CLEAR_COMPL) {
		send_local_rlsd(link, &result);
	} else if (rc == BSS_FILTER_RLC || rc == BSS_FILTER_RLSD) {
		LOGP(DMSC, LOGL_DEBUG, "Not forwarding RLC/RLSD to the MSC.\n");
		return;
	}


	msc_send_msg(&bsc, rc, &result, _msg);
}

/*
 * handle local message in close down mode
 */
static void handle_local_sccp(struct mtp_link *link, struct msgb *inpt, struct sccp_parse_result *result, int sls)
{
	/* Handle msg with a reject */
	if (inpt->l2h[0] == SCCP_MSG_TYPE_CR) {
		struct sccp_connection_request *cr;
		struct msgb *msg;

		LOGP(DINP, LOGL_NOTICE, "Handling CR localy.\n");
		cr = (struct sccp_connection_request *) inpt->l2h;
		msg = create_sccp_refuse(&cr->source_local_reference);
		if (msg) {
			mtp_link_submit_sccp_data(link, sls, msg->l2h, msgb_l2len(msg));
			msgb_free(msg);
		}
		return;
	} else if (inpt->l2h[0] == SCCP_MSG_TYPE_DT1 && result->data_len >= 3) {
		struct active_sccp_con *con;
		struct sccp_data_form1 *form1;
		struct msgb *msg;

		if (inpt->l3h[0] == 0 && inpt->l3h[2] == BSS_MAP_MSG_CLEAR_COMPLETE) {
			LOGP(DINP, LOGL_DEBUG, "Received Clear Complete. Sending Release.\n");

			form1 = (struct sccp_data_form1 *) inpt->l2h;

			llist_for_each_entry(con, &bsc.sccp_connections, entry) {
				if (memcmp(&form1->destination_local_reference,
					   &con->dst_ref, sizeof(con->dst_ref)) == 0) {
					LOGP(DINP, LOGL_DEBUG, "Sending a release request now.\n");
					msg = create_sccp_rlsd(&con->dst_ref, &con->src_ref);
					if (msg) {
						mtp_link_submit_sccp_data(link, con->sls, msg->l2h, msgb_l2len(msg));
						msgb_free(msg);
					}
					return;
				}
			}

			LOGP(DINP, LOGL_ERROR, "Could not find connection for the Clear Command.\n");
		}
	} else if (inpt->l2h[0] == SCCP_MSG_TYPE_UDT && result->data_len >= 3) {
		if (inpt->l3h[0] == 0 && inpt->l3h[2] == BSS_MAP_MSG_RESET_ACKNOWLEDGE) {
			LOGP(DINP, LOGL_NOTICE, "Reset ACK. Connecting to the MSC again.\n");
			bsc_resources_released(&bsc);
			return;
		}
	}


	/* Update the state, maybe the connection was released? */
	update_con_state(0, result, inpt, 0, sls);
	if (llist_empty(&bsc.sccp_connections))
		bsc_resources_released(&bsc);
	return;
}

/*
 * remove data
 */
static void free_con(struct active_sccp_con *con)
{
	llist_del(&con->entry);
	bsc_del_timer(&con->rlc_timeout);
	talloc_free(con);
}

static void clear_connections(struct bsc_data *bsc)
{
	struct active_sccp_con *tmp, *con;

	llist_for_each_entry_safe(con, tmp, &bsc->sccp_connections, entry) {
		free_con(con);
	}

	bsc->link.clear_queue(&bsc->link);
}

void bsc_resources_released(struct bsc_data *bsc)
{
	bsc_del_timer(&bsc->reset_timeout);
	msc_schedule_reconnect(bsc);
}

static void bsc_reset_timeout(void *_data)
{
	struct msgb *msg;
	struct bsc_data *bsc = (struct bsc_data *) _data;

	/* no reset */
	if (bsc->reset_count > 0) {
		LOGP(DINP, LOGL_ERROR, "The BSC did not answer the GSM08.08 reset. Restart MTP\n");
		mtp_link_stop(bsc->link.the_link);
		clear_connections(bsc);
		bsc->link.reset(&bsc->link);
		bsc_resources_released(bsc);
		return;
	}

	msg = create_reset();
	if (!msg) {
		bsc_schedule_timer(&bsc->reset_timeout, 10, 0);
		return;
	}

	++bsc->reset_count;
	mtp_link_submit_sccp_data(bsc->link.the_link, 13, msg->l2h, msgb_l2len(msg));
	msgb_free(msg);
	bsc_schedule_timer(&bsc->reset_timeout, 20, 0);
}

/*
 * We have lost the connection to the MSC. This is tough. We
 * can not just bring down the MTP link as this will disable
 * the BTS radio. We will have to do the following:
 *
 *  1.) Bring down all open SCCP connections. As this will close
 *      all radio resources
 *  2.) Bring down all MGCP endpoints
 *  3.) Clear the connection data.
 *
 * To make things worse we need to buffer the BSC messages... atfer
 * everything has been sent we will try to connect to the MSC again.
 *
 * We will have to veriy that all connections are closed properly..
 * this means we need to parse response message. In the case the
 * MTP link is going down while we are sending. We will simply
 * reconnect to the MSC.
 */
void release_bsc_resources(struct bsc_data *bsc)
{
	struct active_sccp_con *tmp;
	struct active_sccp_con *con;

	bsc->closing = 1;
	bsc_del_timer(&bsc->reset_timeout);

	/* 2. clear the MGCP endpoints */
	mgcp_reset(bsc);

	/* 1. send BSSMAP Cleanup.. if we have any connection */
	llist_for_each_entry_safe(con, tmp, &bsc->sccp_connections, entry) {
		if (!con->has_dst_ref) {
			free_con(con);
			continue;
		}

		struct msgb *msg = create_clear_command(&con->src_ref);
		if (!msg)
			continue;

		/* wait for the clear commands */
		mtp_link_submit_sccp_data(bsc->link.the_link, con->sls, msg->l2h, msgb_l2len(msg));
		msgb_free(msg);
	}

	if (llist_empty(&bsc->sccp_connections)) {
		bsc_resources_released(bsc);
	} else {
		/* Send a reset in 20 seconds if we fail to bring everything down */
		bsc->reset_timeout.cb = bsc_reset_timeout;
		bsc->reset_timeout.data = bsc;
		bsc->reset_count = 0;
		bsc_schedule_timer(&bsc->reset_timeout, 10, 0);
	}

	/* clear pending messages from the MSC */
	while (!llist_empty(&bsc->link.the_link->pending_msgs)) {
		struct msgb *msg = msgb_dequeue(&bsc->link.the_link->pending_msgs);
		msgb_free(msg);
	}
}

void bsc_link_down(struct link_data *data)
{
	int was_up;
	struct mtp_link *link = data->the_link;

	link->available = 0;
	was_up = link->sccp_up;
	mtp_link_stop(link);
	clear_connections(data->bsc);
	mgcp_reset(data->bsc);

	data->clear_queue(data);

	/* clear pending messages from the MSC */
	while (!llist_empty(&link->pending_msgs)) {
		struct msgb *msg = msgb_dequeue(&link->pending_msgs);
		msgb_free(msg);
	}

	/* for the case the link is going down while we are trying to reset */
	if (data->bsc->closing)
		msc_schedule_reconnect(data->bsc);
	else if (was_up)
		msc_send_reset(data->bsc);
}

void bsc_link_up(struct link_data *data)
{
	data->the_link->available = 1;

	/* we have not gone through link down */
	if (data->bsc->closing) {
		clear_connections(data->bsc);
		bsc_resources_released(data->bsc);
	}

	mtp_link_reset(data->the_link);

	if (flood)
		start_flood();
}

/**
 * update the connection state and helpers below
 */
static struct active_sccp_con *find_con_by_dest_ref(struct sccp_source_reference *ref)
{
	struct active_sccp_con *con;

	if (!ref) {
		LOGP(DINP, LOGL_ERROR, "Dest Reference is NULL. No connection found.\n");
		return NULL;
	}

	llist_for_each_entry(con, &bsc.sccp_connections, entry) {
		if (memcmp(&con->dst_ref, ref, sizeof(*ref)) == 0)
			return con;
	}

	LOGP(DINP, LOGL_ERROR, "No connection fond with: 0x%x as dest\n", sccp_src_ref_to_int(ref));
	return NULL;
}

static struct active_sccp_con *find_con_by_src_ref(struct sccp_source_reference *src_ref)
{
	struct active_sccp_con *con;

	/* it is quite normal to not find this one */
	if (!src_ref)
		return NULL;

	llist_for_each_entry(con, &bsc.sccp_connections, entry) {
		if (memcmp(&con->src_ref, src_ref, sizeof(*src_ref)) == 0)
			return con;
	}

	return NULL;
}

static struct active_sccp_con *find_con_by_src_dest_ref(struct sccp_source_reference *src_ref,
							struct sccp_source_reference *dst_ref)
{
	struct active_sccp_con *con;

	llist_for_each_entry(con, &bsc.sccp_connections, entry) {
		if (memcmp(src_ref, &con->src_ref, sizeof(*src_ref)) == 0 &&
		    memcmp(dst_ref, &con->dst_ref, sizeof(*dst_ref)) == 0) {
			return con;
		}
	}

	return NULL;
}

unsigned int sls_for_src_ref(struct sccp_source_reference *ref)
{
	struct active_sccp_con *con;

	con = find_con_by_src_ref(ref);
	if (!con)
		return 13;
	return con->sls;
}

static void send_rlc_to_bsc(unsigned int sls, struct sccp_source_reference *src, struct sccp_source_reference *dst)
{
	struct msgb *msg;

	msg = create_sccp_rlc(src, dst);
	if (!msg)
		return;

	mtp_link_submit_sccp_data(bsc.link.the_link, sls, msg->l2h, msgb_l2len(msg));
	msgb_free(msg);
}

static void handle_rlsd(struct sccp_connection_released *rlsd, int from_msc)
{
	struct active_sccp_con *con;

	if (from_msc) {
		/* search for a connection, reverse src/dest for MSC */
		con = find_con_by_src_dest_ref(&rlsd->destination_local_reference,
					       &rlsd->source_local_reference);
		if (con) {
			LOGP(DINP, LOGL_DEBUG, "RLSD conn still alive: local: 0x%x remote: 0x%x\n",
			     sccp_src_ref_to_int(&con->src_ref),
			     sccp_src_ref_to_int(&con->dst_ref));
			con->released_from_msc = 1;
		} else {
			/* send RLC */
			LOGP(DINP, LOGL_DEBUG, "Sending RLC for MSC: src: 0x%x dst: 0x%x\n",
			     sccp_src_ref_to_int(&rlsd->destination_local_reference),
			     sccp_src_ref_to_int(&rlsd->source_local_reference));
			msc_send_rlc(&bsc, &rlsd->destination_local_reference,
				 &rlsd->source_local_reference);
		}
	} else {
		unsigned int sls = 13;
		con = find_con_by_src_dest_ref(&rlsd->source_local_reference,
					       &rlsd->destination_local_reference);
		if (con) {
			LOGP(DINP, LOGL_DEBUG, "Timeout on BSC. Sending RLC. src: 0x%x\n",
			     sccp_src_ref_to_int(&rlsd->source_local_reference));

			if (con->released_from_msc)
				msc_send_rlc(&bsc, &con->src_ref, &con->dst_ref);
			sls = con->sls;
			free_con(con);
		} else {
			LOGP(DINP, LOGL_ERROR, "Timeout on BSC for unknown connection. src: 0x%x\n",
			     sccp_src_ref_to_int(&rlsd->source_local_reference));
		}

		/* now send a rlc back to the BSC */
		send_rlc_to_bsc(sls, &rlsd->destination_local_reference, &rlsd->source_local_reference);
	}
}

/**
 * Update connection state and also send message.....
 *
 * RLSD from MSC:
 *      1.) We don't find the entry in this case we will send a
 *          forged RLC to the MSC and we are done.
 *      2.) We find an entry in this we will need to register that
 *          we need to send a RLC and we are done for now.
 * RLSD from BSC:
 *      1.) This is an error we are ignoring for now.
 * RLC from BSC:
 *      1.) We are destroying the connection, we might send a RLC to
 *          the MSC if we are waiting for one.
 */
void update_con_state(int rc, struct sccp_parse_result *res, struct msgb *msg, int from_msc, int sls)
{
	struct active_sccp_con *con;
	struct sccp_connection_request *cr;
	struct sccp_connection_confirm *cc;
	struct sccp_connection_release_complete *rlc;
	struct sccp_connection_refused *cref;

	/* was the header okay? */
	if (rc < 0)
		return;

	/* the header was size checked */
	switch (msg->l2h[0]) {
	case SCCP_MSG_TYPE_CR:
		if (from_msc) {
			LOGP(DMSC, LOGL_ERROR, "CR from MSC is not handled.\n");
			return;
		}

		cr = (struct sccp_connection_request *) msg->l2h;
		con = find_con_by_src_ref(&cr->source_local_reference);
		if (con) {
			LOGP(DINP, LOGL_ERROR, "Duplicate SRC reference for: 0x%x. Reusing\n",
				sccp_src_ref_to_int(&con->src_ref));
			free_con(con);
		}

		con = talloc_zero(NULL, struct active_sccp_con);
		if (!con) {
			LOGP(DINP, LOGL_ERROR, "Failed to allocate\n");
			return;
		}

		con->src_ref = cr->source_local_reference;
		con->sls = sls;
		llist_add_tail(&con->entry, &bsc.sccp_connections);
		LOGP(DINP, LOGL_DEBUG, "Adding CR: local ref: 0x%x\n", sccp_src_ref_to_int(&con->src_ref));
		break;
	case SCCP_MSG_TYPE_CC:
		if (!from_msc) {
			LOGP(DINP, LOGL_ERROR, "CC from BSC is not handled.\n");
			return;
		}

		cc = (struct sccp_connection_confirm *) msg->l2h;
		con = find_con_by_src_ref(&cc->destination_local_reference);
		if (con) {
			con->dst_ref = cc->source_local_reference;
			con->has_dst_ref = 1;
			LOGP(DINP, LOGL_DEBUG, "Updating CC: local: 0x%x remote: 0x%x\n",
				sccp_src_ref_to_int(&con->src_ref), sccp_src_ref_to_int(&con->dst_ref));
			return;
		}

		LOGP(DINP, LOGL_ERROR, "CCed connection can not be found: 0x%x\n",
		     sccp_src_ref_to_int(&cc->destination_local_reference));
		break;
	case SCCP_MSG_TYPE_CREF:
		if (!from_msc) {
			LOGP(DINP, LOGL_ERROR, "CREF from BSC is not handled.\n");
			return;
		}

		cref = (struct sccp_connection_refused *) msg->l2h;
		con = find_con_by_src_ref(&cref->destination_local_reference);
		if (con) {
			LOGP(DINP, LOGL_DEBUG, "Releasing local: 0x%x\n", sccp_src_ref_to_int(&con->src_ref));
			free_con(con);
			return;
		}

		LOGP(DINP, LOGL_ERROR, "CREF from BSC is not handled.\n");
		break;
	case SCCP_MSG_TYPE_RLSD:
		handle_rlsd((struct sccp_connection_released *) msg->l2h, from_msc);
		break;
	case SCCP_MSG_TYPE_RLC:
		if (from_msc) {
			LOGP(DINP, LOGL_ERROR, "RLC from MSC is wrong.\n");
			return;
		}

		rlc = (struct sccp_connection_release_complete *) msg->l2h;
		con = find_con_by_src_dest_ref(&rlc->source_local_reference,
					       &rlc->destination_local_reference);
		if (con) {
			LOGP(DINP, LOGL_DEBUG, "Releasing local: 0x%x\n", sccp_src_ref_to_int(&con->src_ref));
			if (con->released_from_msc)
				msc_send_rlc(&bsc, &con->src_ref, &con->dst_ref);
			free_con(con);
			return;
		}

		LOGP(DINP, LOGL_ERROR, "RLC can not be found. 0x%x 0x%x\n",
		     sccp_src_ref_to_int(&rlc->source_local_reference),
		     sccp_src_ref_to_int(&rlc->destination_local_reference));
		break;
	}
}

static void send_local_rlsd_for_con(void *data)
{
	struct msgb *rlsd;
	struct active_sccp_con *con = (struct active_sccp_con *) data;

	/* try again in three seconds */
	con->rlc_timeout.data = con;
	con->rlc_timeout.cb = send_local_rlsd_for_con;
	bsc_schedule_timer(&con->rlc_timeout, 3, 0);

	/* we send this to the BSC so we need to switch src and dest */
	rlsd = create_sccp_rlsd(&con->dst_ref, &con->src_ref);
	if (!rlsd)
		return;

	++con->rls_tries;
	LOGP(DINP, LOGL_DEBUG, "Sending RLSD for 0x%x the %d time.\n",
	     sccp_src_ref_to_int(&con->src_ref), con->rls_tries);
	mtp_link_submit_sccp_data(bsc.link.the_link, con->sls, rlsd->l2h, msgb_l2len(rlsd));
	msgb_free(rlsd);
}

static void send_local_rlsd(struct mtp_link *link, struct sccp_parse_result *res)
{
	struct active_sccp_con *con;

	LOGP(DINP, LOGL_DEBUG, "Received GSM Clear Complete. Sending RLSD locally.\n");

	con = find_con_by_dest_ref(res->destination_local_reference);
	if (!con)
		return;
	con->rls_tries = 0;
	send_local_rlsd_for_con(con);
}

static void send_reset_ack(struct mtp_link *link, int sls)
{
	static const uint8_t reset_ack[] = {
		0x09, 0x00, 0x03, 0x05, 0x7, 0x02, 0x42, 0xfe,
		0x02, 0x42, 0xfe, 0x03,
		0x00, 0x01, 0x31
	};

	mtp_link_submit_sccp_data(link, sls, reset_ack, sizeof(reset_ack));
}

static void start_flood()
{
	static unsigned int i = 0;
	static const uint8_t paging_cmd[] = {
		0x09, 0x00, 0x03,  0x07, 0x0b, 0x04, 0x43, 0x0a,
		0x00, 0xfe, 0x04,  0x43, 0x5c, 0x00, 0xfe, 0x10,
		0x00, 0x0e, 0x52,  0x08, 0x08, 0x29, 0x80, 0x10,
		0x76, 0x10, 0x77,  0x46, 0x05, 0x1a, 0x01, 0x06 };

	/* change the imsi slightly */
	if (bsc.link.the_link->sltm_pending) {
		LOGP(DINP, LOGL_ERROR, "Not sending due clash with SLTM.\n");
	} else {
		struct msgb *msg;
		msg = msgb_alloc_headroom(4096, 128, "paging");
		if (msg) {
			LOGP(DINP, LOGL_NOTICE, "Flooding BSC with one paging requests.\n");

			msg->l2h = msgb_put(msg, sizeof(paging_cmd));
			memcpy(msg->l2h, paging_cmd, msgb_l2len(msg));

			bss_rewrite_header_to_bsc(msg,
						  bsc.link.the_link->opc,
						  bsc.link.the_link->dpc);
			mtp_link_submit_sccp_data(bsc.link.the_link, i++,
						  msg->l2h, msgb_l2len(msg));
			msgb_free(msg);
		}
	}

	/* try again in five seconds */
	flood_timer.cb = start_flood;
	bsc_schedule_timer(&flood_timer, 2, 0);
}

static void print_usage()
{
	printf("Usage: cellmgr_ng\n");
}

static void sigint()
{
	static pthread_mutex_t exit_mutex = PTHREAD_MUTEX_INITIALIZER;
	static int handled = 0;

	/* failed to lock */
	if (pthread_mutex_trylock(&exit_mutex) != 0)
		return;
	if (handled)
		goto out;

	printf("Terminating.\n");
	handled = 1;
	if (bsc.setup)
		bsc.link.shutdown(&bsc.link);
	exit(0);

out:
	pthread_mutex_unlock(&exit_mutex);
}

static void sigusr2()
{
	printf("Closing the MSC connection on demand.\n");
	msc_close_connection(&bsc);
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -c --config=CFG The config file to use.\n");
	printf("  -p --pcap=FILE. Write MSUs to the PCAP file.\n");
	printf("  -c --once. Send the SLTM msg only once.\n");
	printf("  -f --flood. Send flood of paging requests to the BSC.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config", 1, 0, 'c'},
			{"pcap", 1, 0, 'p'},
			{"flood", 0, 0, 'f'},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "hc:p:f",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'p':
			if (bsc.link.pcap_fd >= 0)
				close(bsc.link.pcap_fd);
			bsc.link.pcap_fd = open(optarg, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP| S_IROTH);
			if (bsc.link.pcap_fd < 0) {
				fprintf(stderr, "Failed to open PCAP file.\n");
				exit(0);
			}
			mtp_pcap_write_header(bsc.link.pcap_fd);
			break;
		case 'c':
			config = optarg;
			break;
		case 'f':
			flood = 1;
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			break;
		}
	}
}

static void start_rest(void *start)
{
	bsc.setup = 1;

	if (msc_init(&bsc) != 0) {
		fprintf(stderr, "Failed to init MSC part.\n");
		exit(3);
	}

	bsc.link.start(&bsc.link);
}


int main(int argc, char **argv)
{
	INIT_LLIST_HEAD(&bsc.sccp_connections);

	mtp_link_init();
	thread_init();

	log_init(&log_info);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);

	/* enable filters */
	log_set_all_filter(stderr_target, 1);
	log_set_category_filter(stderr_target, DINP, 1, LOGL_INFO);
	log_set_category_filter(stderr_target, DSCCP, 1, LOGL_INFO);
	log_set_category_filter(stderr_target, DMSC, 1, LOGL_INFO);
	log_set_category_filter(stderr_target, DMGCP, 1, LOGL_INFO);
	log_set_print_timestamp(stderr_target, 1);
	log_set_use_color(stderr_target, 0);

	sccp_set_log_area(DSCCP);

	bsc.setup = 0;
	bsc.msc_address = "127.0.0.1";
	bsc.link.pcap_fd = -1;
	bsc.link.udp.reset_timeout = 180;
	bsc.ping_time = 20;
	bsc.pong_time = 5;
	bsc.msc_time = 20;

	handle_options(argc, argv);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, sigint);
	signal(SIGUSR2, sigusr2);
	srand(time(NULL));

	cell_vty_init();
	if (vty_read_config_file(config, NULL) < 0) {
		fprintf(stderr, "Failed to read the VTY config.\n");
		return -1;
	}

	bsc.link.the_link = mtp_link_alloc();
	bsc.link.the_link->dpc = dpc;
	bsc.link.the_link->opc = opc;
	bsc.link.the_link->link = 0;
	bsc.link.the_link->sltm_once = once;
	bsc.link.bsc = &bsc;

	if (udp_ip) {
		LOGP(DINP, LOGL_NOTICE, "Using UDP MTP mode.\n");

		/* setup SNMP first, it is blocking */
		bsc.link.udp.session = snmp_mtp_session_create(udp_ip);
		if (!bsc.link.udp.session)
			return -1;

		/* now connect to the transport */
		if (link_udp_init(&bsc.link, src_port, udp_ip, udp_port) != 0)
			return -1;

		/* 
		 * We will ask the MTP link to be taken down for two
		 * timeouts of the BSC to make sure we are missing the
		 * SLTM and it begins a reset. Then we will take it up
		 * again and do the usual business.
		 */
		snmp_mtp_deactivate(bsc.link.udp.session);
		bsc.start_timer.cb = start_rest;
		bsc.start_timer.data = &bsc;
		bsc_schedule_timer(&bsc.start_timer, bsc.link.udp.reset_timeout, 0);
		LOGP(DMSC, LOGL_NOTICE, "Making sure SLTM will timeout.\n");
	} else {
		LOGP(DINP, LOGL_NOTICE, "Using NexusWare C7 input.\n");
		if (link_c7_init(&bsc.link) != 0)
			return -1;

		/* give time to things to start*/
		bsc.start_timer.cb = start_rest;
		bsc.start_timer.data = &bsc;
		bsc_schedule_timer(&bsc.start_timer, 30, 0);
		LOGP(DMSC, LOGL_NOTICE, "Waiting to continue to startup.\n");
	}


        while (1) {
		bsc_select_main(0);
        }

	return 0;
}

/* vty code */
enum cellmgr_node {
	CELLMGR_NODE = _LAST_OSMOVTY_NODE,
};

static struct cmd_node cell_node = {
	CELLMGR_NODE,
	"%s(cellmgr)#",
	1,
};

static int config_write_cell()
{
	return CMD_SUCCESS;
}

DEFUN(cfg_cell, cfg_cell_cmd,
      "cellmgr", "Configure the Cellmgr")
{
	vty->node = CELLMGR_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_dpc, cfg_net_dpc_cmd,
      "mtp dpc DPC_NR",
      "Set the DPC to be used.")
{
	dpc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_opc, cfg_net_opc_cmd,
      "mtp opc OPC_NR",
      "Set the OPC to be used.")
{
	opc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_dst_ip, cfg_udp_dst_ip_cmd,
      "udp dest ip IP",
      "Set the IP when UDP mode is supposed to be used.")
{
	struct hostent *hosts;
	struct in_addr *addr;

	hosts = gethostbyname(argv[0]);
	if (!hosts || hosts->h_length < 1 || hosts->h_addrtype != AF_INET) {
		vty_out(vty, "Failed to resolve '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	addr = (struct in_addr *) hosts->h_addr_list[0];
	udp_ip = talloc_strdup(NULL, inet_ntoa(*addr));
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_dst_port, cfg_udp_dst_port_cmd,
      "udp dest port PORT_NR",
      "If UDP mode is used specify the UDP dest port")
{
	udp_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_src_port, cfg_udp_src_port_cmd,
      "udp src port PORT_NR",
      "Set the UDP source port to be used.")
{
	src_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_reset, cfg_udp_reset_cmd,
      "udp reset TIMEOUT",
      "Set the timeout to take the link down")
{
	bsc.link.udp.reset_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_sltm_once, cfg_sltm_once_cmd,
      "mtp sltm once (0|1)",
      "Send SLTMs until the link is established.")
{
	once = !!atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_ip, cfg_msc_ip_cmd,
      "msc ip IP",
      "Set the MSC IP")
{
	struct hostent *hosts;
	struct in_addr *addr;

	hosts = gethostbyname(argv[0]);
	if (!hosts || hosts->h_length < 1 || hosts->h_addrtype != AF_INET) {
		vty_out(vty, "Failed to resolve '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	addr = (struct in_addr *) hosts->h_addr_list[0];

	bsc.msc_address = talloc_strdup(NULL, inet_ntoa(*addr));
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_ip_dscp, cfg_msc_ip_dscp_cmd,
      "msc ip-dscp <0-255>",
      "Set the IP DSCP on the A-link\n"
      "Set the DSCP in IP packets to the MSC")
{
	bsc.msc_ip_dscp = atoi(argv[0]);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_msc_ip_dscp, cfg_msc_ip_tos_cmd,
      "msc ip-tos <0-255>",
      "Set the IP DSCP on the A-link\n"
      "Set the DSCP in IP packets to the MSC")

DEFUN(cfg_msc_token, cfg_msc_token_cmd,
      "msc token TOKEN",
      "Set the Token to be used for the MSC")
{
	bsc.token = talloc_strdup(NULL, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_ping_time, cfg_ping_time_cmd,
      "timeout ping NR",
      "Set the PING interval. Negative to disable it")
{
	bsc.ping_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_pong_time, cfg_pong_time_cmd,
      "timeout pong NR",
      "Set the PING interval. Negative to disable it")
{
	bsc.pong_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_time, cfg_msc_time_cmd,
      "timeout msc NR",
      "Set the MSC connect timeout")
{
	bsc.msc_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

static void cell_vty_init(void)
{
	cmd_init(1);
	vty_init(&vty_info);

	install_element(CONFIG_NODE, &cfg_cell_cmd);
	install_node(&cell_node, config_write_cell);

	install_element(CELLMGR_NODE, &cfg_net_dpc_cmd);
	install_element(CELLMGR_NODE, &cfg_net_opc_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_dst_ip_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_dst_port_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_src_port_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_reset_cmd);
	install_element(CELLMGR_NODE, &cfg_sltm_once_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_ip_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_token_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_ip_dscp_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_ip_tos_cmd);
	install_element(CELLMGR_NODE, &cfg_ping_time_cmd);
	install_element(CELLMGR_NODE, &cfg_pong_time_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_time_cmd);
}

const char *openbsc_copyright = "";
