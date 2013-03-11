/* Run SCCP over IP/TCP/IPA */
/* (C) 2011-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#ifndef sccp_lite_h
#define sccp_lite_h

#include "mtp_data.h"

struct sccp_lite_link {
	struct mtp_link *base;

	int active;
	int established;
	struct sccp_lite_conn *conn;

	/* token handling for pseudo-authentication */
	char *token;

	/* back pointer and management */
	struct mtp_transport *transport;
};

struct mtp_transport *sccp_lite_transp_create(struct bsc_data *bsc);
int sccp_lite_transp_bind(struct mtp_transport *trans, const char *ip, int port);

#endif
