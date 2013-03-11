/* Run SCCP over IP/TCP/IPA here */
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

#include <sccp_lite.h>
#include <cellmgr_debug.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <unistd.h>

static int sccp_lite_transp_accept(struct osmo_fd *fd, unsigned int what)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int s;

	s = accept(fd->fd, (struct sockaddr *) &addr, &len);
	if (s < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to accept.\n");
		return -1;
	}

	LOGP(DINP, LOGL_NOTICE, "Socket handling not implemented yet.\n");
	close(s);
	return 0;
}

struct mtp_transport *sccp_lite_transp_create(struct bsc_data *bsc)
{
	return mtp_transport_create(bsc);
}

int sccp_lite_transp_bind(struct mtp_transport *transp,
			const char *ip, int port)
{
	transp->bsc.cb = sccp_lite_transp_accept;
	return mtp_transport_bind(transp, IPPROTO_TCP, ip, port);
}
