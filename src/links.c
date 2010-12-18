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
#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <snmp_mtp.h>

void link_stop_all(struct bsc_data *bsc)
{
	struct link_data *link;

	llist_for_each_entry(link, &bsc->links, entry)
		mtp_link_stop(link->the_link);
}

void link_reset_all(struct bsc_data *bsc)
{
	struct link_data *link;

	llist_for_each_entry(link, &bsc->links, entry)
		mtp_link_reset(link->the_link);
}

void link_start_all(struct bsc_data *bsc)
{
	struct link_data *link;

	llist_for_each_entry(link, &bsc->links, entry)
		link->start(link);
}

void link_shutdown_all(struct bsc_data *bsc)
{
	struct link_data *link;

	llist_for_each_entry(link, &bsc->links, entry)
		link->shutdown(link);
}

void link_set_pcap_fd(struct bsc_data *bsc)
{
	struct link_data *link;

	llist_for_each_entry(link, &bsc->links, entry)
		link->pcap_fd = bsc->pcap_fd;
}

void link_set_reset_timeout(struct bsc_data *bsc)
{
	struct link_data *link;

	llist_for_each_entry(link, &bsc->links, entry)
		link->udp.reset_timeout = bsc->udp_reset_timeout;
}

static void start_rest(void *start)
{
	struct bsc_data *bsc = start;
	bsc->setup = 1;

	if (msc_init(bsc, 1) != 0) {
		fprintf(stderr, "Failed to init MSC part.\n");
		exit(3);
	}

	link_start_all(bsc);
}

int link_setup_start(struct bsc_data *bsc)
{
	bsc->first_link.the_link = mtp_link_alloc();
	bsc->first_link.the_link->data = &bsc->first_link;
	bsc->first_link.the_link->dpc = bsc->dpc;
	bsc->first_link.the_link->opc = bsc->opc;
	bsc->first_link.the_link->sccp_opc = bsc->sccp_opc > -1 ? bsc->sccp_opc : bsc->opc;
	bsc->first_link.the_link->link = 0;
	bsc->first_link.the_link->sltm_once = bsc->once;
	bsc->first_link.the_link->ni = bsc->ni_ni;
	bsc->first_link.the_link->spare = bsc->ni_spare;
	bsc->first_link.bsc = bsc;
	bsc->first_link.pcap_fd = bsc->pcap_fd;
	bsc->first_link.udp.reset_timeout = bsc->udp_reset_timeout;

	llist_add(&bsc->first_link.entry, &bsc->links);

	if (bsc->udp_ip) {
		LOGP(DINP, LOGL_NOTICE, "Using UDP MTP mode.\n");

		/* setup SNMP first, it is blocking */
		bsc->first_link.udp.session = snmp_mtp_session_create(bsc->udp_ip);
		if (!bsc->first_link.udp.session)
			return -1;

		/* now connect to the transport */
		if (link_udp_init(&bsc->first_link, bsc->src_port, bsc->udp_ip, bsc->udp_port) != 0)
			return -1;

		/*
		 * We will ask the MTP link to be taken down for two
		 * timeouts of the BSC to make sure we are missing the
		 * SLTM and it begins a reset. Then we will take it up
		 * again and do the usual business.
		 */
		snmp_mtp_deactivate(bsc->first_link.udp.session);
		bsc->start_timer.cb = start_rest;
		bsc->start_timer.data = bsc;
		bsc_schedule_timer(&bsc->start_timer, bsc->udp_reset_timeout, 0);
		LOGP(DMSC, LOGL_NOTICE, "Making sure SLTM will timeout.\n");
	} else {
		LOGP(DINP, LOGL_NOTICE, "Using NexusWare C7 input.\n");
		if (link_c7_init(&bsc->first_link) != 0)
			return -1;

		/* give time to things to start*/
		bsc->start_timer.cb = start_rest;
		bsc->start_timer.data = bsc;
		bsc_schedule_timer(&bsc->start_timer, 30, 0);
		LOGP(DMSC, LOGL_NOTICE, "Waiting to continue to startup.\n");
	}

	return 0;
}

/*
 * methods called from the MTP Level3 part
 */
void mtp_link_submit(struct mtp_link *_link, struct msgb *msg)
{
	struct link_data *link = _link->data;
	link->write(link, msg);
}

void mtp_link_restart(struct mtp_link *_link)
{
	struct link_data *link = _link->data;

	LOGP(DINP, LOGL_ERROR, "Need to restart the SS7 link.\n");
	link->reset(link);
}

void mtp_link_sccp_down(struct mtp_link *_link)
{
	struct link_data *link = _link->data;
	msc_clear_queue(link->bsc);
}
