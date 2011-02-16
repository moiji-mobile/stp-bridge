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
#include <ss7_application.h>

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

struct bsc_data *bsc;
extern void cell_vty_init(void);

/*
 * methods called from the MTP Level3 part
 */
void mtp_link_set_forward_sccp(struct mtp_link_set *set, struct msgb *_msg, int sls)
{
	struct mtp_link_set *other;
	if (!set->app) {
		LOGP(DINP, LOGL_ERROR, "Linkset %d/%s does not have an app.\n",
		     set->no, set->name);
		return;
	}

	other = set->app->route_src.set == set ?
			set->app->route_dst.set : set->app->route_src.set;
	mtp_link_set_submit_sccp_data(other, sls, _msg->l2h, msgb_l2len(_msg));
}

void mtp_link_set_forward_isup(struct mtp_link_set *set, struct msgb *msg, int sls)
{
	struct mtp_link_set *other;
	if (!set->app) {
		LOGP(DINP, LOGL_ERROR, "Linkset %d/%s does not have an app.\n",
		     set->no, set->name);
		return;
	}

	other = set->app->route_src.set == set ?
			set->app->route_dst.set : set->app->route_src.set;
	mtp_link_set_submit_isup_data(other, sls, msg->l3h, msgb_l3len(msg));
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

static struct mtp_link_set *find_link_set(struct bsc_data *bsc,
					  int len, const char *buf)
{
	struct mtp_link_set *set;

	llist_for_each_entry(set, &bsc->linksets, entry)
		if (strncmp(buf, set->name, len) == 0)
			return set;

	return NULL;
}

static int inject_read_cb(struct bsc_fd *fd, unsigned int what)
{
	struct msgb *msg;
	struct m2ua_msg_part *data, *link;
	struct bsc_data *bsc;
	struct m2ua_msg *m2ua;
	struct mtp_link_set *out_set;
	uint8_t buf[4096];

	bsc = fd->data;

	int rc = read(fd->fd, buf, sizeof(buf));
	if (rc <= 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to read from the console.\n");
		return -1;
	}

	if (!bsc->allow_inject) {
		LOGP(DINP, LOGL_ERROR, "Injecting messages is not allowed.\n");
		return -1;
	}

	m2ua = m2ua_from_msg(rc, buf);
	if (!m2ua) {
		LOGP(DINP, LOGL_ERROR, "Failed to parse M2UA.\n");
		return -1;
	}

	if (m2ua->hdr.msg_class == M2UA_CLS_MAUP && m2ua->hdr.msg_type == M2UA_MAUP_DATA) {
		data = m2ua_msg_find_tag(m2ua, M2UA_TAG_DATA);
		if (!data) {
			LOGP(DINP, LOGL_ERROR, "MAUP Data without data.\n");
			goto exit;
		}

		if (data->len > 2048) {
			LOGP(DINP, LOGL_ERROR, "Data is too big for this configuration.\n");
			goto exit;
		}

		link = m2ua_msg_find_tag(m2ua, MUA_TAG_IDENT_TEXT);
		if (!link) {
			LOGP(DINP, LOGL_ERROR, "Interface Identifier Text is mandantory.\n");
			goto exit;
		}

		if (link->len > 255) {
			LOGP(DINP, LOGL_ERROR, "Spec violation. Ident text should be shorter than 255.\n");
			goto exit;
		}

		out_set = find_link_set(bsc, link->len, (const char *) link->dat);
		if (!out_set) {
			LOGP(DINP, LOGL_ERROR, "Identified linkset does not exist.\n");
			goto exit;
		}

		msg = msgb_alloc(2048, "inject-data");
		if (!msg) {
			LOGP(DINP, LOGL_ERROR, "Failed to allocate storage.\n");
			goto exit;
		}

		msg->l2h = msgb_put(msg, data->len);
		memcpy(msg->l2h, data->dat, data->len);

		/* we are diretcly going to the output. no checking of anything  */
		if (mtp_link_set_send(out_set, msg) != 0) {
			LOGP(DINP, LOGL_ERROR, "Failed to send message.\n");
			msgb_free(msg);
		}
	}

exit:
	m2ua_msg_free(m2ua);
	return 0;
}

static int inject_init(struct bsc_data *bsc)
{
	int fd;
	struct sockaddr_in addr;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(5001);

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to bind to port 5001.\n");
		close(fd);
		return -1;
	}

	bsc->inject_fd.fd = fd;
	bsc->inject_fd.when = BSC_FD_READ;
	bsc->inject_fd.cb = inject_read_cb;
	bsc->inject_fd.data = bsc;

	if (bsc_register_fd(&bsc->inject_fd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register.\n");
		close(fd);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int rc;
	struct mtp_link *data;
	struct mtp_link_set *set;
	struct mtp_link_set *m2ua_set;
	struct mtp_m2ua_link *lnk;
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
	m2ua_set_log_area(DM2UA);

	bsc = bsc_data_create();
	if (!bsc)
		return -1;
	bsc->app = APP_STP;

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

	if (inject_init(bsc) != 0) {
		LOGP(DINP, LOGL_NOTICE, "Failed to initialize inject interface.\n");
		return -1;
	}

	app = ss7_application_alloc(bsc);
	if (!app)
		return -1;

	set = link_init(bsc);
	if (!set)
		return -1;

	bsc->m2ua_trans = sctp_m2ua_transp_create("0.0.0.0", 2904);
	if (!bsc->m2ua_trans) {
		LOGP(DINP, LOGL_ERROR, "Failed to create SCTP transport.\n");
		return -1;
	}

	m2ua_set = mtp_link_set_alloc(bsc);
	m2ua_set->dpc = 92;
	m2ua_set->opc = 9;
	m2ua_set->sccp_opc = 9;
	m2ua_set->isup_opc = 9;
	m2ua_set->ni = 3;
	m2ua_set->bsc = bsc;
	m2ua_set->pcap_fd = bsc->pcap_fd;
	m2ua_set->name = talloc_strdup(m2ua_set, "M2UA");

	/* setup things */
	set->pass_all_isup = bsc->isup_pass;
	m2ua_set->pass_all_isup = bsc->isup_pass;

	lnk = mtp_m2ua_link_create(m2ua_set);
	lnk->base.pcap_fd = -1;
	mtp_link_set_add_link(m2ua_set, (struct mtp_link *) lnk);

	ss7_application_setup(app, APP_STP,
			      SS7_SET_LINKSET, 0,
			      SS7_SET_LINKSET, 1);

	llist_for_each_entry(data, &m2ua_set->links, entry)
		data->start(data);

        while (1) {
		bsc_select_main(0);
        }

	return 0;
}

/* dummy for links */
int msc_connection_start(struct msc_connection *conn)
{
	return 0;
}

struct msc_connection *msc_connection_num(struct bsc_data *bsc, int num)
{
	return NULL;
}
