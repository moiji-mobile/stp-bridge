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

#include <isup_types.h>
#include <cellmgr_debug.h>
#include <mtp_data.h>

#include <osmocore/msgb.h>
#include <osmocore/tlv.h>

static struct msgb *isup_gra_alloc(int cic, int range)
{
	struct isup_msg_hdr *hdr;
	struct msgb *msg;
	int bits, len;

	msg = msgb_alloc_headroom(4096, 128, "ISUP GRA");
	if (!msg) {
		LOGP(DISUP, LOGL_ERROR, "Allocation of GRA message failed.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*hdr));

	/* write the ISUP header */
	hdr = (struct isup_msg_hdr *) msg->l2h;
	hdr->cic = cic;
	hdr->msg_type = ISUP_MSG_GRA;

	/*
	 * place the pointers here.
	 * 1.) place the variable start after us
	 * 2.) place the length
	 */
	msgb_v_put(msg, 1);

	bits = range + 1;
	len = (bits / 8) + 1;
	msgb_v_put(msg, len + 1);
	msgb_v_put(msg, range);

	msgb_put(msg, len);

	return msg;
}

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
static int handle_circuit_reset_grs(struct mtp_link_set *link, int sls, int cic,
				    const uint8_t *data, int size)
{
	struct msgb *resp;
	int range;

	range = isup_parse_grs(data, size);
	if (range < 0)
		return -1;

	resp = isup_gra_alloc(cic, range);
	if (!resp)
		return -1;

	mtp_link_set_submit_isup_data(link, sls, resp->l2h, msgb_l2len(resp));
	msgb_free(resp);
	return 0;
}

int mtp_link_set_isup(struct mtp_link_set *link, struct msgb *msg, int sls)
{
	int rc = -1;
	int payload_size;
	struct isup_msg_hdr *hdr;

	if (msgb_l3len(msg) < sizeof(*hdr)) {
		LOGP(DISUP, LOGL_ERROR, "ISUP header is too short.\n");
		return -1;
	}

	if (link->pass_all_isup) {
		mtp_link_set_forward_isup(link, msg, sls);
		return 0;
	}

	hdr = (struct isup_msg_hdr *) msg->l3h;
	payload_size = msgb_l3len(msg) - sizeof(*hdr);

	switch (hdr->msg_type) {
	case ISUP_MSG_GRS:
		rc = handle_circuit_reset_grs(link, sls, hdr->cic, hdr->data, payload_size);
		break;
	default:
		mtp_link_set_forward_isup(link, msg, sls);
		rc = 0;
		break;
	}

	return rc;
}
