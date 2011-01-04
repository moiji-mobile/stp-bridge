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

void mtp_link_down(struct link_data *link)
{
	mtp_linkset_down(link->the_link);
	link->clear_queue(link);
	mtp_link_set_init_slc(link->the_link);
}

void mtp_link_up(struct link_data *link)
{
	mtp_linkset_up(link->the_link);
	mtp_link_set_init_slc(link->the_link);
}

void mtp_link_set_sccp_down(struct mtp_link_set *link)
{
}

void mtp_link_set_submit(struct link_data *link, struct msgb *msg)
{
	link->write(link, msg);
}

void mtp_link_set_restart(struct mtp_link_set *set)
{
	LOGP(DINP, LOGL_ERROR, "Need to restart the SS7 link.\n");
	set->link->reset(set->link);
}

static void start_rest(void *start)
{
	bsc.setup = 1;

	if (msc_init(&bsc, 1) != 0) {
		fprintf(stderr, "Failed to init MSC part.\n");
		exit(3);
	}

	bsc.link_set->link->start(bsc.link_set->link);
}

int link_init(struct bsc_data *bsc)
{
	bsc->link_set = mtp_link_set_alloc();
	bsc->link_set->dpc = bsc->dpc;
	bsc->link_set->opc = bsc->opc;
	bsc->link_set->sccp_opc = bsc->sccp_opc > -1 ? bsc->sccp_opc : bsc->opc;
	bsc->link_set->sltm_once = bsc->once;
	bsc->link_set->ni = bsc->ni_ni;
	bsc->link_set->spare = bsc->ni_spare;
	bsc->link_set->bsc = bsc;

	bsc->link_set->link = talloc_zero(bsc->link_set, struct link_data);
	bsc->link_set->link->bsc = bsc;
	bsc->link_set->link->udp.link_index = 1;
	bsc->link_set->link->pcap_fd = bsc->pcap_fd;
	bsc->link_set->link->udp.reset_timeout = bsc->udp_reset_timeout;
	bsc->link_set->link->the_link = bsc->link_set;

	if (!bsc->src_port) {
		LOGP(DINP, LOGL_ERROR, "You need to set a UDP address.\n");
		return -1;
	}

	LOGP(DINP, LOGL_NOTICE, "Using UDP MTP mode.\n");

	/* setup SNMP first, it is blocking */
	bsc->link_set->link->udp.session = snmp_mtp_session_create(bsc->udp_ip);
	if (!bsc->link_set->link->udp.session)
		return -1;

	/* now connect to the transport */
	if (link_udp_init(bsc->link_set->link, bsc->src_port, bsc->udp_ip, bsc->udp_port) != 0)
		return -1;

	/*
	 * We will ask the MTP link to be taken down for two
	 * timeouts of the BSC to make sure we are missing the
	 * SLTM and it begins a reset. Then we will take it up
	 * again and do the usual business.
	 */
	snmp_mtp_deactivate(bsc->link_set->link->udp.session,
			    bsc->link_set->link->udp.link_index);
	bsc->start_timer.cb = start_rest;
	bsc->start_timer.data = &bsc;
	bsc_schedule_timer(&bsc->start_timer, bsc->link_set->link->udp.reset_timeout, 0);
	LOGP(DMSC, LOGL_NOTICE, "Making sure SLTM will timeout.\n");

	return 0;
}
