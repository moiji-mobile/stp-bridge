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
	bsc->first_link.udp.link_index = 1;

	llist_add(&bsc->first_link.entry, &bsc->links);

	if (!bsc->first_link.udp.udp_ip) {
		LOGP(DINP, LOGL_ERROR, "Need to set a UDP IP.\n");
		return -1;
	}

	LOGP(DINP, LOGL_NOTICE, "Using UDP MTP mode.\n");

	/* setup SNMP first, it is blocking */
	bsc->first_link.udp.session = snmp_mtp_session_create(bsc->first_link.udp.udp_ip);
	if (!bsc->first_link.udp.session)
		return -1;

	if (link_udp_network_init(bsc) != 0)
		return -1;

	/* now connect to the transport */
	if (link_udp_init(&bsc->first_link, bsc->first_link.udp.udp_ip, bsc->first_link.udp.udp_port) != 0)
		return -1;

	/*
	 * We will ask the MTP link to be taken down for two
	 * timeouts of the BSC to make sure we are missing the
	 * SLTM and it begins a reset. Then we will take it up
	 * again and do the usual business.
	 */
	snmp_mtp_deactivate(bsc->first_link.udp.session,
			    bsc->first_link.udp.link_index);
	bsc->start_timer.cb = start_rest;
	bsc->start_timer.data = bsc;
	bsc_schedule_timer(&bsc->start_timer, bsc->udp_reset_timeout, 0);
	LOGP(DMSC, LOGL_NOTICE, "Making sure SLTM will timeout.\n");

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
}

static struct mtp_link *find_for_sls(struct bsc_data *bsc, int sls)
{
	struct link_data *link;

	llist_for_each_entry(link, &bsc->links, entry)
		return link->the_link;

	return NULL;
}

int linkset_send_bsc_msg(struct bsc_data *bsc, int sls, struct msgb *msg)
{
	return linkset_send_bsc_data(bsc, sls, msg->l2h, msgb_l2len(msg));
}

int linkset_send_bsc_data(struct bsc_data *bsc, int sls, const uint8_t *data, int len)
{
	struct mtp_link *link;

	link = find_for_sls(bsc, sls);
	if (!link) {
		LOGP(DINP, LOGL_ERROR, "No MTPLink for SLS: %d\n", sls);
		return 0;
	}

	if (!link->sccp_up) {
		LOGP(DINP, LOGL_ERROR, "SCCP is not up on the linkset.\n");
		return 0;
	}

	if (mtp_link_submit_sccp_data(link, sls, data, len) != 0)
		LOGP(DMSC, LOGL_ERROR, "Could not forward SCCP message.\n");
	return 0;
}

/* One of the links of the linkset failed */
void bsc_link_down(struct link_data *data)
{
	struct link_data *link;
	struct bsc_data *bsc;
	int one_up = 0;

	bsc = data->bsc;
	data->the_link->available = 0;

	llist_for_each_entry(link, &bsc->links, entry)
		one_up |= link->the_link->available;


	mtp_link_stop(data->the_link);

	if (!one_up)
		bsc_linkset_down(bsc);

	data->clear_queue(data);
}

/* One of the links of the linkset is back */
void bsc_link_up(struct link_data *data)
{
	struct link_data *link;
	struct bsc_data *bsc;
	int one_up = 0;

	bsc = data->bsc;
	llist_for_each_entry(link, &bsc->links, entry)
		one_up |= link->the_link->available;

	data->the_link->available = 1;

	/* if at least one link is back... report it as up */
	if (!one_up)
		bsc_linkset_up(bsc);

	mtp_link_reset(data->the_link);
}

void mtp_link_forward_sccp(struct mtp_link *_link, struct msgb *_msg, int sls)
{
	struct link_data *link = _link->data;

	linkset_forward_sccp(link->bsc, _msg, sls);
}
