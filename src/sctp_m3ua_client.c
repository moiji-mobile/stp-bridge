/* Run M3UA over SCTP here */
/* (C) 2015 by Holger Hans Peter Freyther
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <sctp_m3ua.h>
#include <cellmgr_debug.h>

#include <osmocom/core/talloc.h>

#define SCTP_PPID_M3UA 3

#define notImplemented							\
		LOGP(DINP, LOGL_NOTICE, "%s:%s not implemented.\n",	\
			__FILE__, __func__);

static int m3ua_write(struct mtp_link *mtp_link, struct msgb *msg)
{
	msgb_free(msg);
	return 0;
}

static int m3ua_shutdown(struct mtp_link *mtp_link)
{
	return 0;
}

static int m3ua_reset(struct mtp_link *mtp_link)
{
	/* let the framework call start again */
	return m3ua_shutdown(mtp_link);
}

static int m3ua_clear_queue(struct mtp_link *mtp_link)
{
	/* nothing */
	return 0;
}

struct mtp_m3ua_client_link *mtp_m3ua_client_link_init(struct mtp_link *blnk)
{
	struct mtp_m3ua_client_link *lnk;

	lnk = talloc_zero(blnk, struct mtp_m3ua_client_link);
	if (!lnk) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	/* make sure we can resolve it both ways */
	lnk->base = blnk;
	blnk->data = lnk;
	blnk->type = SS7_LTYPE_M3UA_CLIENT;

	/* do some checks for lower layer handling */
	blnk->skip_link_test = 1;

	lnk->base->write = m3ua_write;
	lnk->base->shutdown = m3ua_shutdown;
	lnk->base->reset = m3ua_reset;
	lnk->base->clear_queue = m3ua_clear_queue;
	return lnk;
}
