/* link management code */
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

#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <mtp_data.h>
#include <snmp_mtp.h>

#include <osmocore/talloc.h>

extern struct bsc_data bsc;

int is_one_up(struct mtp_link_set *set)
{
	struct mtp_link *entry;

	llist_for_each_entry(entry, &set->links, entry)
		if (entry->available)
			return 1;
	return 0;
}

void mtp_link_down(struct mtp_link *link)
{
	int one_up;
	int was_up;

	was_up = link->available;
	link->available = 0;
	one_up = is_one_up(link->the_link);

	/* our linkset is now unsuable */
	if (was_up && !one_up)
		mtp_linkset_down(link->the_link);
	link->clear_queue(link);
	mtp_link_set_init_slc(link->the_link);
}

void mtp_link_up(struct mtp_link *link)
{
	int one_up;

	one_up = is_one_up(link->the_link);
	link->available = 1;

	mtp_link_set_init_slc(link->the_link);
	if (!one_up)
		mtp_linkset_up(link->the_link);
}

void mtp_link_set_sccp_down(struct mtp_link_set *link)
{
}

void mtp_link_set_submit(struct mtp_link *link, struct msgb *msg)
{
	link->write(link, msg);
}

void mtp_link_restart(struct mtp_link *link)
{
	LOGP(DINP, LOGL_ERROR, "Need to restart the SS7 link.\n");
	link->reset(link);
}

static void start_rest(void *start)
{
	struct mtp_link *data;
	bsc.setup = 1;

	if (msc_init(&bsc, 1) != 0) {
		fprintf(stderr, "Failed to init MSC part.\n");
		exit(3);
	}

	llist_for_each_entry(data, &bsc.link_set->links, entry)
		data->start(data);
}

int link_init(struct bsc_data *bsc)
{
	struct mtp_udp_link *lnk;

	bsc->link_set = mtp_link_set_alloc();
	bsc->link_set->dpc = bsc->dpc;
	bsc->link_set->opc = bsc->opc;
	bsc->link_set->sccp_opc = bsc->sccp_opc > -1 ? bsc->sccp_opc : bsc->opc;
	bsc->link_set->sltm_once = bsc->once;
	bsc->link_set->ni = bsc->ni_ni;
	bsc->link_set->spare = bsc->ni_spare;
	bsc->link_set->bsc = bsc;

	lnk = talloc_zero(bsc->link_set, struct mtp_udp_link);
	lnk->base.pcap_fd = bsc->pcap_fd;
	lnk->base.the_link = bsc->link_set;
	lnk->bsc = bsc;
	lnk->link_index = 1;
	lnk->reset_timeout = bsc->udp_reset_timeout;
	mtp_link_set_add_link(bsc->link_set, (struct mtp_link *) lnk);

	if (!bsc->src_port) {
		LOGP(DINP, LOGL_ERROR, "You need to set a UDP address.\n");
		return -1;
	}

	LOGP(DINP, LOGL_NOTICE, "Using UDP MTP mode.\n");

	/* setup SNMP first, it is blocking */
	lnk->session = snmp_mtp_session_create(bsc->udp_ip);
	if (!lnk->session)
		return -1;

	/* now connect to the transport */
	if (link_udp_init(lnk, bsc->src_port, bsc->udp_ip, bsc->udp_port) != 0)
		return -1;

	/*
	 * We will ask the MTP link to be taken down for two
	 * timeouts of the BSC to make sure we are missing the
	 * SLTM and it begins a reset. Then we will take it up
	 * again and do the usual business.
	 */
	snmp_mtp_deactivate(lnk->session,
			    lnk->link_index);
	bsc->start_timer.cb = start_rest;
	bsc->start_timer.data = &bsc;
	bsc_schedule_timer(&bsc->start_timer, lnk->reset_timeout, 0);
	LOGP(DMSC, LOGL_NOTICE, "Making sure SLTM will timeout.\n");

	return 0;
}

int link_shutdown_all(struct mtp_link_set *set)
{
	struct mtp_link *lnk;

	llist_for_each_entry(lnk, &set->links, entry)
		lnk->shutdown(lnk);
	return 0;
}

int link_reset_all(struct mtp_link_set *set)
{
	struct mtp_link *lnk;

	llist_for_each_entry(lnk, &set->links, entry)
		lnk->reset(lnk);
	return 0;
}

int link_clear_all(struct mtp_link_set *set)
{
	struct mtp_link *lnk;

	llist_for_each_entry(lnk, &set->links, entry)
		lnk->clear_queue(lnk);
	return 0;
}
