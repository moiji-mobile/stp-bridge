/* MGCP message patching */
/*
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by On-Waves
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
 */

#include <mgcp_patch.h>
#include <cellmgr_debug.h>
#include <ss7_application.h>
#include <string.h>

#include <osmocom/gsm/tlv.h>


struct msgb *mgcp_patch(struct ss7_application *app, struct msgb *msg)
{
	char *token, *remaining;
	struct msgb *out;
	int len, out_len, state, i;

	if (!app->mgcp_domain_name)
		return msg;

	if (msgb_tailroom(msg) <= strlen(app->mgcp_domain_name)) {
		LOGP(DMGCP, LOGL_ERROR, "Not enough space to add a zero line.\n");
		return msg;
	}

	msg->l2h[msgb_l2len(msg)] = '\0';

	/**
	 * We now need to rewrite the message, but actually only the first
	 * line and the rest can be copied.
	 */
	out = msgb_alloc_headroom(4096, 128, "MGCP Patch Copy");
	if (!out) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create the MSGB copy.\n");
		return NULL;
	}


	remaining = (char *) msg->l2h;
	token = strsep(&remaining, "\n");
	if (!token) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to split the MGCP.\n");
		msgb_free(out);
		return msg;
	}

	len = strlen(token);
	out->l2h = msgb_put(out, 0);

	/*
	 * State machine for copying and modifying the MGCP line, first find
	 * half of the endpoint, put ours, copy the rest of the line
	 */
	state = 0;
	for (i = 0; i < len; ++i) {
		switch (state) {
		case 2:
			if (token[i] == '@')
				state += 1;
			msgb_v_put(out, token[i]);
			break;
		case 3:
			/* copy the new name */
			out->l3h = msgb_put(out, strlen(app->mgcp_domain_name));
			memcpy(out->l3h, app->mgcp_domain_name, msgb_l3len(out));

			/* skip everything to the next whitespace */
			for (; i < len; ++i) {
				if (token[i] == ' ') {
					break;
				}
			}

			for (; i < len; ++i)
				msgb_v_put(out, token[i]);
			msgb_v_put(out, '\n');
			break;
		default:
			if (token[i] == ' ')
				state += 1;
			msgb_v_put(out, token[i]);
			break;
		}
	}

	/* append the rest */
	out_len = msgb_l2len(msg) - len - 1;
	out->l3h = msgb_put(out, out_len);
	memcpy(out->l3h, &msg->l2h[len + 1], out_len);

	msgb_free(msg);
	return out;
}

