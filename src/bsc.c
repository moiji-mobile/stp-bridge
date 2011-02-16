/* Everything related to the global BSC */
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

#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <mtp_level3.h>

#include <osmocore/talloc.h>

struct bsc_data *bsc_data_create()
{
	struct bsc_data *bsc;

	bsc = talloc_zero(NULL, struct bsc_data);
	if (!bsc) {
		LOGP(DINP, LOGL_ERROR, "Failed to create the BSC.\n");
		return NULL;
	}

	INIT_LLIST_HEAD(&bsc->linksets);
	INIT_LLIST_HEAD(&bsc->mscs);
	INIT_LLIST_HEAD(&bsc->apps);

	bsc->dpc = 1;
	bsc->opc = 0;
	bsc->sccp_opc = -1;
	bsc->isup_opc = -1;
	bsc->udp_port = 3456;
	bsc->udp_ip = NULL;
	bsc->udp_nr_links = 1;
	bsc->src_port = 1313;
	bsc->ni_ni = MTP_NI_NATION_NET;
	bsc->ni_spare = 0;
	bsc->pcap_fd = -1;
	bsc->udp_reset_timeout = 180;

	return bsc;
}
