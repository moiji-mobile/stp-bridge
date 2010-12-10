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

#include <isup_types.h>
#include <cellmgr_debug.h>

#include <osmocore/msgb.h>

/* this message contains the range */
int isup_parse_grs(const uint8_t *data, uint8_t in_length)
{
	uint8_t ptr;
	uint8_t length;

	if (in_length > 3) {
		LOGP(DISUP, LOGL_ERROR, "This needs three bytes.\n");
		return -1;	
	}

	ptr = data[0];
	if (1 + ptr > in_length) {
		LOGP(DISUP, LOGL_ERROR, "Pointing outside the packet.\n");
		return -1;
	}

	length = data[0 + ptr];

	if (1 + ptr + 1 > in_length) {
		LOGP(DISUP, LOGL_ERROR, "No space for the data.\n");
		return -1;
	}

	return data[0 + ptr + 1];
}


/* Handle incoming ISUP data */
static int handle_circuit_reset_grs(struct mtp_link *link, int sls,
				    const uint8_t *data, int size)
{
	int range;

	range = isup_parse_grs(data, size);
	if (range < 0)
		return -1;

	printf("ASKED to reset range: %d\n", range);

	return 0;
}

int mtp_link_forward_isup(struct mtp_link *link, struct msgb *msg, int sls)
{
	int rc = -1;
	int payload_size;
	struct isup_msg_hdr *hdr;

	if (msgb_l3len(msg) < sizeof(*hdr)) {
		LOGP(DISUP, LOGL_ERROR, "ISUP header is too short.\n");
		return -1;
	}

	hdr = (struct isup_msg_hdr *) msg->l3h;
	payload_size = msgb_l3len(msg) - sizeof(*hdr);

	switch (hdr->msg_type) {
	case ISUP_MSG_GRS:
		rc = handle_circuit_reset_grs(link, sls, hdr->data, payload_size);
		break;
	default:
		LOGP(DISUP, LOGL_NOTICE, "ISUP msg not handled: 0x%x\n", hdr->msg_type);
		break;
	}

	return rc;
}
