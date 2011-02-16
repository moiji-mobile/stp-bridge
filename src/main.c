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
#include <msc_connection.h>
#include <mtp_level3.h>
#include <mtp_pcap.h>
#include <thread.h>
#include <bss_patch.h>
#include <bssap_sccp.h>
#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <bsc_sccp.h>
#include <ss7_application.h>

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

struct bsc_data *bsc;
extern void cell_vty_init(void);

static void print_usage()
{
	printf("Usage: cellmgr_ng\n");
}

static void sigint()
{
	static pthread_mutex_t exit_mutex = PTHREAD_MUTEX_INITIALIZER;
	static int handled = 0;

	struct mtp_link_set *set;

	/* failed to lock */
	if (pthread_mutex_trylock(&exit_mutex) != 0)
		return;
	if (handled)
		goto out;

	printf("Terminating.\n");
	handled = 1;
	if (bsc && bsc->setup) {
		llist_for_each_entry(set, &bsc->linksets, entry)
			link_shutdown_all(set);
	}

	exit(0);

out:
	pthread_mutex_unlock(&exit_mutex);
}

static void sigusr2()
{
	struct msc_connection *msc;
	printf("Closing the MSC connection on demand.\n");

	llist_for_each_entry(msc, &bsc->mscs, entry)
		msc_close_connection(msc);
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
			if (bsc->pcap_fd >= 0)
				close(bsc->pcap_fd);
			bsc->pcap_fd = open(optarg, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP| S_IROTH);
			if (bsc->pcap_fd < 0) {
				fprintf(stderr, "Failed to open PCAP file.\n");
				exit(0);
			}
			mtp_pcap_write_header(bsc->pcap_fd);
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

static void bsc_msc_forward_init(struct msc_connection *msc)
{
	msc->ip = talloc_strdup(msc, "127.0.0.1");
	msc->ping_time = 20;
	msc->pong_time = 5;
	msc->msc_time = 20;
}

int main(int argc, char **argv)
{
	int rc;
	struct msc_connection *msc;
	struct mtp_link_set *set;
	struct ss7_application *app;

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

	bsc = bsc_data_create();
	if (!bsc)
		return -1;
	bsc->app = APP_CELLMGR;

	/* msc data */
	msc = msc_connection_create(bsc, 1);
	if (!msc) {
		LOGP(DINP, LOGL_ERROR, "Failed to create the MSC connection.\n");
		return -1;
	}
	bsc_msc_forward_init(msc);

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

	set = link_init(bsc);
	if (!set)
		return -1;

	app = ss7_application_alloc(bsc);
	if (!app) {
		LOGP(DINP, LOGL_ERROR, "Failed to create the SS7 application.\n");
		return -1;
	}

	ss7_application_setup(app, APP_CELLMGR,
			      SS7_SET_LINKSET, 0,
			      SS7_SET_MSC, 0);

        while (1) {
		bsc_select_main(0);
        }

	return 0;
}

