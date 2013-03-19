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
#include <msc_connection.h>
#include <mtp_data.h>
#include <mtp_level3.h>
#include <mtp_pcap.h>

extern struct bsc_data *bsc;

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
		link_set_down(link->set);
	link->clear_queue(link);
	mtp_link_stop_link_test(link);
	mtp_link_set_init_slc(link->set);
}

void mtp_link_up(struct mtp_link *link)
{
	int one_up;

	if (link->blocked) {
		LOGP(DINP, LOGL_ERROR,
		     "Ignoring link up on blocked link %d/%s of linkset %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		return;
	}

	one_up = is_one_up(link->set);
	link->available = 1;
	link->was_up = 0;

	mtp_link_set_init_slc(link->set);
	if (!one_up)
		link_set_up(link->set);
	else
		mtp_link_start_link_test(link);
}

void mtp_link_restart(struct mtp_link *link)
{
	LOGP(DINP, LOGL_ERROR, "Need to restart the SS7 link.\n");
	link->reset(link);
}

int mtp_handle_pcap(struct mtp_link *link, int dir, const uint8_t *data, int len)
{
	if (link->pcap_fd >= 0)
		mtp_pcap_write_msu(link->pcap_fd, data, len);
	if (link->set->pcap_fd >= 0)
		mtp_pcap_write_msu(link->set->pcap_fd, data, len);

	/* This might be too expensive? */
	LOGP(DPCAP, LOGL_NOTICE, "Packet: %s\n", osmo_hexdump(data, len));
	return 0;
}
