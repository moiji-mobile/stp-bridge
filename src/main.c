/* Bloated main routine, refactor */
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

#include <mtp_data.h>
#include <mtp_level3.h>
#include <mtp_pcap.h>
#include <thread.h>
#include <bss_patch.h>
#include <bssap_sccp.h>
#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <bsc_sccp.h>

#include <osmocore/talloc.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>

#undef PACKAGE_NAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#undef PACKAGE_TARNAME
#undef PACKAGE_STRING
#include <cellmgr_config.h>

static struct log_target *stderr_target;

static char *config = "cellmgr_ng.cfg";

struct bsc_data bsc;
extern void cell_vty_init(void);

static void send_reset_ack(struct mtp_link_set *link, int sls);
static void bsc_resources_released(struct bsc_data *bsc);
static void handle_local_sccp(struct mtp_link_set *link, struct msgb *inp, struct sccp_parse_result *res, int sls);
static void clear_connections(struct bsc_data *bsc);
static void send_local_rlsd(struct mtp_link_set *link, struct sccp_parse_result *res);

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
void mtp_link_set_forward_sccp(struct mtp_link_set *link, struct msgb *_msg, int sls)
{
	int rc;
	struct sccp_parse_result result;

	rc = bss_patch_filter_msg(_msg, &result);
	if (rc == BSS_FILTER_RESET) {
		LOGP(DMSC, LOGL_NOTICE, "Filtering BSS Reset from the BSC\n");
		mgcp_reset(&bsc);
		send_reset_ack(link, sls);
		return;
	}

	/* special responder */
	if (bsc.msc_link_down) {
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
	update_con_state(link, rc, &result, _msg, 0, sls);

	if (rc == BSS_FILTER_CLEAR_COMPL) {
		send_local_rlsd(link, &result);
	} else if (rc == BSS_FILTER_RLC || rc == BSS_FILTER_RLSD) {
		LOGP(DMSC, LOGL_DEBUG, "Not forwarding RLC/RLSD to the MSC.\n");
		return;
	}


	msc_send_msg(&bsc, rc, &result, _msg);
}

void mtp_link_set_forward_isup(struct mtp_link_set *set, struct msgb *msg, int sls)
{
	LOGP(DINP, LOGL_ERROR, "ISUP is not handled.\n");
}

/*
 * handle local message in close down mode
 */
static void handle_local_sccp(struct mtp_link_set *link, struct msgb *inpt, struct sccp_parse_result *result, int sls)
{
	/* Handle msg with a reject */
	if (inpt->l2h[0] == SCCP_MSG_TYPE_CR) {
		struct sccp_connection_request *cr;
		struct msgb *msg;

		LOGP(DINP, LOGL_NOTICE, "Handling CR localy.\n");
		cr = (struct sccp_connection_request *) inpt->l2h;
		msg = create_sccp_refuse(&cr->source_local_reference);
		if (msg) {
			mtp_link_set_submit_sccp_data(link, sls, msg->l2h, msgb_l2len(msg));
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
						mtp_link_set_submit_sccp_data(link, con->sls, msg->l2h, msgb_l2len(msg));
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
	update_con_state(link, 0, result, inpt, 0, sls);
	if (llist_empty(&bsc.sccp_connections))
		bsc_resources_released(&bsc);
	return;
}

static void clear_connections(struct bsc_data *bsc)
{
	struct active_sccp_con *tmp, *con;

	llist_for_each_entry_safe(con, tmp, &bsc->sccp_connections, entry) {
		free_con(con);
	}

	link_clear_all(bsc->link_set);
}

void bsc_resources_released(struct bsc_data *bsc)
{
	bsc_del_timer(&bsc->reset_timeout);
}

static void bsc_reset_timeout(void *_data)
{
	struct msgb *msg;
	struct bsc_data *bsc = (struct bsc_data *) _data;

	/* no reset */
	if (bsc->reset_count > 0) {
		LOGP(DINP, LOGL_ERROR, "The BSC did not answer the GSM08.08 reset. Restart MTP\n");
		mtp_link_set_stop(bsc->link_set);
		clear_connections(bsc);
		link_reset_all(bsc->link_set);
		bsc_resources_released(bsc);
		return;
	}

	msg = create_reset();
	if (!msg) {
		bsc_schedule_timer(&bsc->reset_timeout, 10, 0);
		return;
	}

	++bsc->reset_count;
	mtp_link_set_submit_sccp_data(bsc->link_set, -1, msg->l2h, msgb_l2len(msg));
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
		mtp_link_set_submit_sccp_data(bsc->link_set, con->sls, msg->l2h, msgb_l2len(msg));
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
}

void mtp_linkset_down(struct mtp_link_set *set)
{
	set->available = 0;
	mtp_link_set_stop(set);
	clear_connections(set->bsc);
	mgcp_reset(set->bsc);

	/* If we have an A link send a reset to the MSC */
	msc_send_reset(set->bsc);
}

void mtp_linkset_up(struct mtp_link_set *set)
{
	set->available = 1;

	/* we have not gone through link down */
	if (set->bsc->msc_link_down) {
		clear_connections(set->bsc);
		bsc_resources_released(set->bsc);
	}

	mtp_link_set_reset(set);
}

/**
 * update the connection state and helpers below
 */
static void send_rlc_to_bsc(unsigned int sls, struct sccp_source_reference *src, struct sccp_source_reference *dst)
{
	struct msgb *msg;

	msg = create_sccp_rlc(src, dst);
	if (!msg)
		return;

	mtp_link_set_submit_sccp_data(bsc.link_set, sls, msg->l2h, msgb_l2len(msg));
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
		unsigned int sls = -1;
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
void update_con_state(struct mtp_link_set *link, int rc, struct sccp_parse_result *res, struct msgb *msg, int from_msc, int sls)
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
		con->link = link;
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
	mtp_link_set_submit_sccp_data(bsc.link_set, con->sls, rlsd->l2h, msgb_l2len(rlsd));
	msgb_free(rlsd);
}

static void send_local_rlsd(struct mtp_link_set *link, struct sccp_parse_result *res)
{
	struct active_sccp_con *con;

	LOGP(DINP, LOGL_DEBUG, "Received GSM Clear Complete. Sending RLSD locally.\n");

	con = find_con_by_dest_ref(res->destination_local_reference);
	if (!con)
		return;
	con->rls_tries = 0;
	send_local_rlsd_for_con(con);
}

static void send_reset_ack(struct mtp_link_set *link, int sls)
{
	static const uint8_t reset_ack[] = {
		0x09, 0x00, 0x03, 0x05, 0x7, 0x02, 0x42, 0xfe,
		0x02, 0x42, 0xfe, 0x03,
		0x00, 0x01, 0x31
	};

	mtp_link_set_submit_sccp_data(link, sls, reset_ack, sizeof(reset_ack));
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
		link_shutdown_all(bsc.link_set);
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
	printf("  -v --version. Print the version number\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config", 1, 0, 'c'},
			{"pcap", 1, 0, 'p'},
			{"version", 0, 0, 0},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "hc:p:v",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'p':
			if (bsc.pcap_fd >= 0)
				close(bsc.pcap_fd);
			bsc.pcap_fd = open(optarg, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP| S_IROTH);
			if (bsc.pcap_fd < 0) {
				fprintf(stderr, "Failed to open PCAP file.\n");
				exit(0);
			}
			mtp_pcap_write_header(bsc.pcap_fd);
			break;
		case 'c':
			config = optarg;
			break;
		case 'v':
			printf("This is %s version %s.\n", PACKAGE, VERSION);
			exit(0);
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			break;
		}
	}
}

int main(int argc, char **argv)
{
	int rc;
	INIT_LLIST_HEAD(&bsc.sccp_connections);

	bsc.dpc = 1;
	bsc.opc = 0;
	bsc.sccp_opc = -1;
	bsc.udp_port = 3456;
	bsc.udp_ip = NULL;
	bsc.src_port = 1313;
	bsc.ni_ni = MTP_NI_NATION_NET;
	bsc.ni_spare = 0;

	mtp_link_set_init();
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
	bsc.pcap_fd = -1;
	bsc.udp_reset_timeout = 180;
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

	rc = telnet_init(NULL, NULL, 4242);
	if (rc < 0)
		return rc;

	if (link_init(&bsc) != 0)
		return -1;

        while (1) {
		bsc_select_main(0);
        }

	return 0;
}

