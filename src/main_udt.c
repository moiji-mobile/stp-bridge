/* Relay UDT/all SCCP messages */
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

#include <mtp_data.h>
#include <mtp_level3.h>
#include <mtp_pcap.h>
#include <thread.h>
#include <bsc_data.h>
#include <snmp_mtp.h>
#include <cellmgr_debug.h>

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

static char *config = "udt_relay.cfg";

struct bsc_data bsc;
extern void cell_vty_init(void);

/*
 * methods called from the MTP Level3 part
 */
void mtp_link_forward_sccp(struct mtp_link *link, struct msgb *_msg, int sls)
{
	msc_send_direct(&bsc, _msg);
}

void bsc_link_down(struct link_data *data)
{
	int was_up;
	struct mtp_link *link = data->the_link;

	link->available = 0;
	was_up = link->sccp_up;
	mtp_link_stop(link);

	data->clear_queue(data);

	/* If we have an A link send a reset to the MSC */
	msc_send_reset(data->bsc);
}

void bsc_link_up(struct link_data *data)
{
	data->the_link->available = 1;
	mtp_link_reset(data->the_link);
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
	bsc.forward_only = 1;

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

void release_bsc_resources(struct bsc_data *bsc)
{
}

struct msgb *create_sccp_rlc(struct sccp_source_reference *src_ref,
			     struct sccp_source_reference *dst)
{
	LOGP(DMSC, LOGL_NOTICE, "Refusing to create connection handling.\n");
	return NULL;
}

struct msgb *create_reset()
{
	LOGP(DMSC, LOGL_NOTICE, "Refusing to create a GSM0808 reset message.\n");
	return NULL;
}

void update_con_state(struct mtp_link *link, int rc, struct sccp_parse_result *res, struct msgb *msg, int from_msc, int sls)
{
	LOGP(DMSC, LOGL_ERROR, "Should not be called.\n");
	return;
}

unsigned int sls_for_src_ref(struct sccp_source_reference *ref)
{
	return 13;
}

int bsc_ussd_handle_in_msg(struct bsc_data *bsc, struct sccp_parse_result *res, struct msgb *msg)
{
	return 0;
}

int bsc_ussd_handle_out_msg(struct bsc_data *bsc, struct sccp_parse_result *res, struct msgb *msg)
{
	return 0;
}
