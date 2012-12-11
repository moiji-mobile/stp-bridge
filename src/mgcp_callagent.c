/*
 * (C) 2010-2012 by Holger Hans Peter Freyther
 * (C) 2010-2012 by On-Waves
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

#include <mgcp_callagent.h>
#include <cellmgr_debug.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static int mgcp_do_write(struct osmo_fd *fd, struct msgb *msg)
{
	int ret;

	LOGP(DMGCP, LOGL_DEBUG, "Sending msg to MGCP GW size: %u\n", msg->len);

	ret = write(fd->fd, msg->data, msg->len);
	if (ret != msg->len) {
		LOGP(DMGCP, LOGL_ERROR,
			"Failed to forward message to MGCP GW (%s).\n",
			strerror(errno));
	}

	return ret;
}

static int mgcp_do_read(struct osmo_fd *fd)
{
	struct mgcp_callagent *agent;
	struct msgb *mgcp;
	int ret;

	agent = fd->data;

	mgcp = msgb_alloc_headroom(4096, 128, "mgcp_from_gw");
	if (!mgcp) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate MGCP message.\n");
		return -1;
	}

	ret = read(fd->fd, mgcp->data, 4096 - 128);
	if (ret <= 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to read: %d/%s\n", errno, strerror(errno));
		msgb_free(mgcp);
		return -1;
	} else if (ret > 4096 - 128) {
		LOGP(DMGCP, LOGL_ERROR, "Too much data: %d\n", ret);
		msgb_free(mgcp);
		return -1; 
        }

	mgcp->l2h = msgb_put(mgcp, ret);
	agent->read_cb(agent, mgcp);
	return 0;
}

int mgcp_create_port(struct mgcp_callagent *agent)
{
	int on;
	struct sockaddr_in addr;

	agent->queue.bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (agent->queue.bfd.fd < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to create UDP socket errno: %d\n", errno);
		return -1;
	}

	on = 1;
	setsockopt(agent->queue.bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* try to bind the socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(agent->queue.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to bind to any port.\n");
		close(agent->queue.bfd.fd);
		agent->queue.bfd.fd = -1;
		return -1;
	}

	/* connect to the remote */
	addr.sin_port = htons(2427);
	if (connect(agent->queue.bfd.fd, (struct sockaddr *) & addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to connect to local MGCP GW. %s\n", strerror(errno));
		close(agent->queue.bfd.fd);
		agent->queue.bfd.fd = -1;
		return -1;
	}

	osmo_wqueue_init(&agent->queue, 10);
	agent->queue.bfd.data = agent;
	agent->queue.bfd.when = BSC_FD_READ;
	agent->queue.read_cb = mgcp_do_read;
	agent->queue.write_cb = mgcp_do_write;

	if (osmo_fd_register(&agent->queue.bfd) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to register BFD\n");
		close(agent->queue.bfd.fd);
		agent->queue.bfd.fd = -1;
		return -1;
	}

	return 0;
}

void mgcp_forward(struct mgcp_callagent *agent, const uint8_t *data,
		unsigned int length)
{
	struct msgb *mgcp;

	if (length > 4096) {
		LOGP(DMGCP, LOGL_ERROR, "Can not forward too big message.\n");
		return;
	}

	mgcp = msgb_alloc(4096, "mgcp_to_gw");
	if (!mgcp) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to send message.\n");
		return;
	}

	msgb_put(mgcp, length);
	memcpy(mgcp->data, data, mgcp->len);
	if (osmo_wqueue_enqueue(&agent->queue, mgcp) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Could not queue message to MGCP GW.\n");
		msgb_free(mgcp);
	}
}

