/* Relay UDT/all SCCP messages */
/*
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
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
#include <mtp_level3.h>
#include <mtp_pcap.h>
#include <thread.h>
#include <bsc_data.h>
#include <snmp_mtp.h>
#include <cellmgr_debug.h>
#include <sctp_m2ua.h>

#include <osmocom/m2ua/m2ua_msg.h>

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

static char *config = "osmo_stp.cfg";

struct bsc_data bsc;
extern void cell_vty_init(void);

/*
 * methods called from the MTP Level3 part
 */
void mtp_link_set_forward_sccp(struct mtp_link_set *link, struct msgb *_msg, int sls)
{
	struct mtp_link_set *target;

	target = bsc.m2ua_set == link ? bsc.link_set : bsc.m2ua_set;
	mtp_link_set_submit_sccp_data(target, sls, _msg->l2h, msgb_l2len(_msg));
}

void mtp_link_set_forward_isup(struct mtp_link_set *set, struct msgb *msg, int sls)
{
	struct mtp_link_set *target;

	target = bsc.m2ua_set == set ? bsc.link_set : bsc.m2ua_set;
	mtp_link_set_submit_isup_data(target, sls, msg->l3h, msgb_l3len(msg));
}

void mtp_linkset_down(struct mtp_link_set *set)
{
	set->available = 0;
	mtp_link_set_stop(set);
}

void mtp_linkset_up(struct mtp_link_set *set)
{
	set->available = 1;
	mtp_link_set_reset(set);
}

static void print_usage()
{
	printf("Usage: osmo-stp\n");
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
	struct mtp_link *data;
	struct mtp_m2ua_link *lnk;
	INIT_LLIST_HEAD(&bsc.sccp_connections);

	bsc.app = APP_STP;
	bsc.dpc = 1;
	bsc.opc = 0;
	bsc.sccp_opc = -1;
	bsc.isup_opc = -1;
	bsc.udp_port = 3456;
	bsc.udp_ip = NULL;
	bsc.src_port = 1313;
	bsc.ni_ni = MTP_NI_NATION_NET;
	bsc.ni_spare = 0;
	bsc.udp_nr_links = 1;

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
	m2ua_set_log_area(DM2UA);

	bsc.setup = 0;
	bsc.msc_address = "127.0.0.1";
	bsc.pcap_fd = -1;
	bsc.udp_reset_timeout = 180;
	bsc.ping_time = 20;
	bsc.pong_time = 5;
	bsc.msc_time = 20;
	bsc.forward_only = 1;

	handle_options(argc, argv);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, sigint);
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

	bsc.m2ua_set = mtp_link_set_alloc();
	bsc.m2ua_set->dpc = 92;
	bsc.m2ua_set->opc = 9;
	bsc.m2ua_set->sccp_opc = 9;
	bsc.m2ua_set->isup_opc = 9;
	bsc.m2ua_set->ni = 3;
	bsc.m2ua_set->bsc = &bsc;
	bsc.m2ua_set->pcap_fd = bsc.pcap_fd;
	bsc.m2ua_set->name = talloc_strdup(bsc.m2ua_set, "M2UA");

	/* for both links we want to have all isup messages */
	bsc.m2ua_set->pass_all_isup = 1;
	bsc.link_set->pass_all_isup = 1;

	lnk = sctp_m2ua_transp_create("0.0.0.0", 2904);
	lnk->base.pcap_fd = -1;
	mtp_link_set_add_link(bsc.m2ua_set, (struct mtp_link *) lnk);

	llist_for_each_entry(data, &bsc.m2ua_set->links, entry)
		data->start(data);

        while (1) {
		bsc_select_main(0);
        }

	return 0;
}

/* dummy for links */
int msc_init(struct bsc_data *data, int dummy)
{
	return 0;
}

