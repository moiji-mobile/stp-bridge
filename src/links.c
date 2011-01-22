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
#include <mtp_pcap.h>
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
	link->was_up = 0;
	one_up = is_one_up(link->set);

	/* our linkset is now unsuable */
	if (was_up && !one_up)
		mtp_linkset_down(link->set);
	link->clear_queue(link);
	mtp_link_stop_link_test(link);
	mtp_link_set_init_slc(link->set);
}

void mtp_link_up(struct mtp_link *link)
{
	int one_up;

	one_up = is_one_up(link->set);
	link->available = 1;
	link->was_up = 0;

	mtp_link_set_init_slc(link->set);
	if (!one_up)
		mtp_linkset_up(link->set);
	else
		mtp_link_start_link_test(link);
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
	int i;
	struct mtp_udp_link *lnk;

	bsc->link_set = mtp_link_set_alloc();
	bsc->link_set->dpc = bsc->dpc;
	bsc->link_set->opc = bsc->opc;
	bsc->link_set->sccp_opc = bsc->sccp_opc > -1 ? bsc->sccp_opc : bsc->opc;
	bsc->link_set->isup_opc = bsc->isup_opc > -1 ? bsc->isup_opc : bsc->opc;
	bsc->link_set->sltm_once = bsc->once;
	bsc->link_set->ni = bsc->ni_ni;
	bsc->link_set->spare = bsc->ni_spare;
	bsc->link_set->bsc = bsc;
	bsc->link_set->pcap_fd = bsc->pcap_fd;

	if (!bsc->src_port) {
		LOGP(DINP, LOGL_ERROR, "You need to set a UDP address.\n");
		return -1;
	}

	LOGP(DINP, LOGL_NOTICE, "Using UDP MTP mode.\n");

	if (link_global_init(&bsc->udp_data, bsc->udp_ip, bsc->src_port) != 0)
		return -1;


	for (i = 1; i <= bsc->udp_nr_links; ++i) {
		lnk = talloc_zero(bsc->link_set, struct mtp_udp_link);
		lnk->base.pcap_fd = -1;
		lnk->bsc = bsc;
		lnk->data = &bsc->udp_data;
		lnk->link_index = i;
		lnk->reset_timeout = bsc->udp_reset_timeout;
		mtp_link_set_add_link(bsc->link_set, (struct mtp_link *) lnk);


		/* now connect to the transport */
		if (link_udp_init(lnk, bsc->udp_ip, bsc->udp_port) != 0)
			return -1;

		/*
		 * We will ask the MTP link to be taken down for two
		 * timeouts of the BSC to make sure we are missing the
		 * SLTM and it begins a reset. Then we will take it up
		 * again and do the usual business.
		 */
		snmp_mtp_deactivate(lnk->data->session,
				    lnk->link_index);
		bsc->start_timer.cb = start_rest;
		bsc->start_timer.data = &bsc;
		bsc_schedule_timer(&bsc->start_timer, lnk->reset_timeout, 0);
		LOGP(DMSC, LOGL_NOTICE, "Making sure SLTM will timeout.\n");
	}

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

int mtp_handle_pcap(struct mtp_link *link, int dir, const uint8_t *data, int len)
{
	if (link->pcap_fd < 0)
		mtp_pcap_write_msu(link->pcap_fd, data, len);
	if (link->set->pcap_fd < 0)
		mtp_pcap_write_msu(link->set->pcap_fd, data, len);

	/* This might be too expensive? */
	LOGP(DPCAP, LOGL_NOTICE, "Packet: %s\n", hexdump(data, len));
	return 0;
}
