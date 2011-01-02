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

extern struct bsc_data bsc;

void mtp_link_sccp_down(struct mtp_link *link)
{
}

void mtp_link_submit(struct mtp_link *link, struct msgb *msg)
{
	bsc.link.write(&bsc.link, msg);
}

void mtp_link_restart(struct mtp_link *link)
{
	LOGP(DINP, LOGL_ERROR, "Need to restart the SS7 link.\n");
	bsc.link.reset(&bsc.link);
}

static void start_rest(void *start)
{
	bsc.setup = 1;

	if (msc_init(&bsc, 1) != 0) {
		fprintf(stderr, "Failed to init MSC part.\n");
		exit(3);
	}

	bsc.link.start(&bsc.link);
}

int link_init(struct bsc_data *bsc)
{
	bsc->link.the_link = mtp_link_alloc();
	bsc->link.the_link->dpc = bsc->dpc;
	bsc->link.the_link->opc = bsc->opc;
	bsc->link.the_link->sccp_opc = bsc->sccp_opc > -1 ? bsc->sccp_opc : bsc->opc;
	bsc->link.the_link->sltm_once = bsc->once;
	bsc->link.the_link->ni = bsc->ni_ni;
	bsc->link.the_link->spare = bsc->ni_spare;
	bsc->link.bsc = bsc;
	bsc->link.udp.link_index = 1;

	if (!bsc->src_port) {
		LOGP(DINP, LOGL_ERROR, "You need to set a UDP address.\n");
		return -1;
	}

	LOGP(DINP, LOGL_NOTICE, "Using UDP MTP mode.\n");

	/* setup SNMP first, it is blocking */
	bsc->link.udp.session = snmp_mtp_session_create(bsc->udp_ip);
	if (!bsc->link.udp.session)
		return -1;

	/* now connect to the transport */
	if (link_udp_init(&bsc->link, bsc->src_port, bsc->udp_ip, bsc->udp_port) != 0)
		return -1;

	/*
	 * We will ask the MTP link to be taken down for two
	 * timeouts of the BSC to make sure we are missing the
	 * SLTM and it begins a reset. Then we will take it up
	 * again and do the usual business.
	 */
	snmp_mtp_deactivate(bsc->link.udp.session,
			    bsc->link.udp.link_index);
	bsc->start_timer.cb = start_rest;
	bsc->start_timer.data = &bsc;
	bsc_schedule_timer(&bsc->start_timer, bsc->link.udp.reset_timeout, 0);
	LOGP(DMSC, LOGL_NOTICE, "Making sure SLTM will timeout.\n");

	return 0;
}
