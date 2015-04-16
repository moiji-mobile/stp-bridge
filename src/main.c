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
#include <osmocom/mtp/mtp_level3.h>
#include <thread.h>
#include <bss_patch.h>
#include <bssap_sccp.h>
#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <bsc_sccp.h>
#include <ss7_application.h>

#include <osmocom/core/application.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/talloc.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>

#include <sys/stat.h>
#include <sys/types.h>

char *config = "cellmgr_ng.cfg";

struct bsc_data *bsc;
extern void cell_vty_init(void);
extern void handle_options(int argc, char **argv);

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

	rate_ctr_init(NULL);

	thread_init();

	osmo_init_logging(&log_info);

	/* enable filters */
	log_set_category_filter(osmo_stderr_target, DINP, 1, LOGL_INFO);
	log_set_category_filter(osmo_stderr_target, DSCCP, 1, LOGL_INFO);
	log_set_category_filter(osmo_stderr_target, DMSC, 1, LOGL_INFO);
	log_set_category_filter(osmo_stderr_target, DMGCP, 1, LOGL_INFO);
	log_set_print_timestamp(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	sccp_set_log_area(DSCCP);

	bsc = bsc_data_create();
	if (!bsc)
		return -1;

	/* msc data */
	msc = msc_connection_create(bsc, 1);
	if (!msc) {
		LOGP(DINP, LOGL_ERROR, "Failed to create the MSC connection.\n");
		return -1;
	}
	bsc_msc_forward_init(msc);

	handle_options(argc, argv);

	srand(time(NULL));

	cell_vty_init();

	set = link_set_create(bsc);
	if (!set) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate the link.\n");
		return -1;
	}

	app = ss7_application_alloc(bsc);
	if (!app) {
		LOGP(DINP, LOGL_ERROR, "Failed to create the SS7 application.\n");
		return -1;
	}

	/* Now parse the configuration file */
	if (vty_read_config_file(config, NULL) < 0) {
		fprintf(stderr, "Failed to read the VTY config.\n");
		return -1;
	}

	rc = telnet_init(NULL, NULL, 4242);
	if (rc < 0)
		return rc;

	/* create the links and start */
	if (link_init(bsc, set) != 0)
		return -1;

	ss7_application_setup(app, APP_CELLMGR,
			      SS7_SET_LINKSET, 0,
			      SS7_SET_MSC, 0);
	ss7_application_start(app);

        while (1) {
		osmo_select_main(0);
        }

	return 0;
}

int sctp_m2ua_conn_count(struct sctp_m2ua_transport *trans)
{
	return 0;
}
