/* MSC related stuff... */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <msc_connection.h>
#include <bsc_data.h>
#include <bsc_sccp.h>
#include <bssap_sccp.h>
#include <ipaccess.h>
#include <mtp_data.h>
#include <cellmgr_debug.h>

#include <osmocom/core/talloc.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/write_queue.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define RECONNECT_TIME		10, 0
#define NAT_MUX 0xfc

static void msc_send_id_response(struct msc_connection *bsc);
static void msc_send(struct msc_connection *bsc, struct msgb *msg, int proto);
static void msc_schedule_reconnect(struct msc_connection *bsc);
static void mgcp_forward(struct msc_connection *fw, const uint8_t *data, unsigned int length);

void msc_close_connection(struct msc_connection *fw)
{
	struct osmo_fd *bfd = &fw->msc_connection.bfd;

	close(bfd->fd);
	osmo_fd_unregister(bfd);
	bfd->fd = -1;
	fw->msc_link_down = 1;
	release_bsc_resources(fw);
	osmo_timer_del(&fw->ping_timeout);
	osmo_timer_del(&fw->pong_timeout);
	osmo_timer_del(&fw->msc_timeout);
	msc_schedule_reconnect(fw);
}

static void msc_connect_timeout(void *_fw_data)
{
	struct msc_connection *fw = _fw_data;

	LOGP(DMSC, LOGL_ERROR, "Timeout on the MSC connection.\n");
	msc_close_connection(fw);
}

static void msc_pong_timeout(void *_fw_data)
{
	struct msc_connection *fw = _fw_data;
	LOGP(DMSC, LOGL_ERROR, "MSC didn't respond to ping. Closing.\n");
	msc_close_connection(fw);
}

static void send_ping(struct msc_connection *fw)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "ping");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create PING.\n");
		return;
	}

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;

	msc_send(fw, msg, IPAC_PROTO_IPACCESS);
}

static void msc_ping_timeout(void *_fw_data)
{
	struct msc_connection *fw = _fw_data;

	if (fw->ping_time < 0)
		return;

	send_ping(fw);

	/* send another ping in 20 seconds */
	osmo_timer_schedule(&fw->ping_timeout, fw->ping_time, 0);

	/* also start a pong timer */
	osmo_timer_schedule(&fw->pong_timeout, fw->pong_time, 0);
}

/*
 * callback with IP access data
 */
static int ipaccess_a_fd_cb(struct osmo_fd *bfd)
{
	int error;
	struct ipaccess_head *hh;
	struct msc_connection *fw;
	struct msgb *msg;

	fw = bfd->data;
	msg = ipaccess_read_msg(bfd, &error);

	if (!msg) {
		if (error == 0)
			fprintf(stderr, "The connection to the MSC was lost, exiting\n");
		else
			fprintf(stderr, "Error in the IPA stream.\n");

		msc_close_connection(fw);
		return -1;
	}

	LOGP(DMSC, LOGL_DEBUG, "From MSC: %s proto: %d\n", osmo_hexdump(msg->data, msg->len), msg->l2h[0]);

	/* handle base message handling */
	hh = (struct ipaccess_head *) msg->data;
	ipaccess_rcvmsg_base(msg, bfd);

	/* initialize the networking. This includes sending a GSM08.08 message */
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		if (fw->first_contact) {
			LOGP(DMSC, LOGL_NOTICE, "Connected to MSC. Sending reset.\n");
			osmo_timer_del(&fw->msc_timeout);
			fw->first_contact = 0;
			fw->msc_link_down = 0;
			msc_send_reset(fw);
		}
		if (msg->l2h[0] == IPAC_MSGT_ID_GET && fw->token) {
			msc_send_id_response(fw);
		} else if (msg->l2h[0] == IPAC_MSGT_PONG) {
			osmo_timer_del(&fw->pong_timeout);
		}
	} else if (hh->proto == IPAC_PROTO_SCCP) {
		msc_dispatch_sccp(fw, msg);
	} else if (hh->proto == NAT_MUX) {
		mgcp_forward(fw, msg->l2h, msgb_l2len(msg));
	} else {
		LOGP(DMSC, LOGL_ERROR, "Unknown IPA proto 0x%x\n", hh->proto);
	}

	msgb_free(msg);
	return 0;
}

static int ipaccess_write_cb(struct osmo_fd *fd, struct msgb *msg)
{
	int rc;

	LOGP(DMSC, LOGL_DEBUG, "Sending to MSC: %s\n", osmo_hexdump(msg->data, msg->len));
	rc = write(fd->fd, msg->data, msg->len);
	if (rc != msg->len)
		LOGP(DMSC, LOGL_ERROR, "Could not write to MSC.\n");

	return rc;
}

/* called in the case of a non blocking connect */
static int msc_connection_connect(struct osmo_fd *fd, unsigned int what)
{
	int rc;
	int val;
	socklen_t len = sizeof(val);
	struct msc_connection *fw;

	fw = fd->data;

	if (fd != &fw->msc_connection.bfd) {
		LOGP(DMSC, LOGL_ERROR, "This is only working with the MSC connection.\n");
		return -1;
	}

	if ((what & BSC_FD_WRITE) == 0)
		return -1;

	/* check the socket state */
	rc = getsockopt(fd->fd, SOL_SOCKET, SO_ERROR, &val, &len);
	if (rc != 0) {
		LOGP(DMSC, LOGL_ERROR, "getsockopt for the MSC socket failed.\n");
		goto error;
	}
	if (val != 0) {
		LOGP(DMSC, LOGL_ERROR, "Not connected to the MSC.\n");
		goto error;
	}


	/* go to full operation */
	fd->cb = osmo_wqueue_bfd_cb;
	fd->when = BSC_FD_READ;
	if (!llist_empty(&fw->msc_connection.msg_queue))
		fd->when |= BSC_FD_WRITE;
	return 0;

error:
	msc_close_connection(fw);
	return -1;
}

static int setnonblocking(struct osmo_fd *fd)
{
	int flags;

	flags = fcntl(fd->fd, F_GETFL);
	if (flags < 0) {
		perror("fcntl get failed");
		close(fd->fd);
		fd->fd = -1;
		return -1;
	}

	flags |= O_NONBLOCK;
	flags = fcntl(fd->fd, F_SETFL, flags);
	if (flags < 0) {
		perror("fcntl get failed");
		close(fd->fd);
		fd->fd = -1;
		return -1;
	}

	return 0;
}

static int connect_to_msc(struct osmo_fd *fd, const char *ip, int port, int tos)
{
	struct sockaddr_in sin;
	int on = 1, ret;

	LOGP(DMSC, LOGL_NOTICE, "Attempting to connect MSC at %s:%d\n", ip, port);

	fd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (fd->fd < 0) {
		perror("Creating TCP socket failed");
		return fd->fd;
	}

	/* make it non blocking */
	if (setnonblocking(fd) != 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	inet_aton(ip, &sin.sin_addr);

	setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	ret = setsockopt(fd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret != 0)
		LOGP(DMSC, LOGL_ERROR, "Failed to set TCP_NODELAY: %s\n", strerror(errno));
	ret = setsockopt(fd->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
	if (ret != 0)
		LOGP(DMSC, LOGL_ERROR, "Failed to set IP_TOS: %s\n", strerror(errno));

	ret = connect(fd->fd, (struct sockaddr *) &sin, sizeof(sin));

	if (ret == -1 && errno == EINPROGRESS) {
		LOGP(DMSC, LOGL_ERROR, "MSC Connection in progress\n");
		fd->when = BSC_FD_WRITE;
		fd->cb = msc_connection_connect;
	} else if (ret < 0) {
		perror("Connection failed");
		close(fd->fd);
		fd->fd = -1;
		return ret;
	} else {
		fd->when = BSC_FD_READ;
		fd->cb = osmo_wqueue_bfd_cb;
	}

	ret = osmo_fd_register(fd);
	if (ret < 0) {
		perror("Registering the fd failed");
		close(fd->fd);
		fd->fd = -1;
		return ret;
	}

	return ret;
}

static void msc_reconnect(void *_data)
{
	int rc;
	struct msc_connection *fw = _data;

	osmo_timer_del(&fw->reconnect_timer);
	fw->first_contact = 1;

	rc = connect_to_msc(&fw->msc_connection.bfd, fw->ip, 5000, fw->dscp);
	if (rc < 0) {
		fprintf(stderr, "Opening the MSC connection failed. Trying again\n");
		osmo_timer_schedule(&fw->reconnect_timer, RECONNECT_TIME);
		return;
	}

	fw->msc_timeout.cb = msc_connect_timeout;
	fw->msc_timeout.data = fw;
	osmo_timer_schedule(&fw->msc_timeout, fw->msc_time, 0);
}

static void msc_schedule_reconnect(struct msc_connection *fw)
{
	osmo_timer_schedule(&fw->reconnect_timer, RECONNECT_TIME);
}

/*
 * mgcp forwarding is below
 */
/* send a RSIP to the MGCP GW */
void msc_mgcp_reset(struct msc_connection *msc)
{
        static const char mgcp_reset[] = {
            "RSIP 1 13@mgw MGCP 1.0\r\n"
        };

	mgcp_forward(msc, (const uint8_t *) mgcp_reset, strlen(mgcp_reset));
}

static int mgcp_do_write(struct osmo_fd *fd, struct msgb *msg)
{
	int ret;

	LOGP(DMGCP, LOGL_DEBUG, "Sending msg to MGCP GW size: %u\n", msg->len);

	ret = write(fd->fd, msg->data, msg->len);
	if (ret != msg->len)
		LOGP(DMGCP, LOGL_ERROR, "Failed to forward message to MGCP GW (%s).\n", strerror(errno));

	return ret;
}

static int mgcp_do_read(struct osmo_fd *fd)
{
	struct msgb *mgcp;
	int ret;

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
	msc_send(fd->data, mgcp, NAT_MUX);
	return 0;
}

static void mgcp_forward(struct msc_connection *fw, const uint8_t *data, unsigned int length)
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
	if (osmo_wqueue_enqueue(&fw->mgcp_agent, mgcp) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Could not queue message to MGCP GW.\n");
		msgb_free(mgcp);
	}
}

static int mgcp_create_port(struct msc_connection *fw)
{
	int on;
	struct sockaddr_in addr;

	fw->mgcp_agent.bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fw->mgcp_agent.bfd.fd < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to create UDP socket errno: %d\n", errno);
		return -1;
	}

	on = 1;
	setsockopt(fw->mgcp_agent.bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* try to bind the socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(fw->mgcp_agent.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to bind to any port.\n");
		close(fw->mgcp_agent.bfd.fd);
		fw->mgcp_agent.bfd.fd = -1;
		return -1;
	}

	/* connect to the remote */
	addr.sin_port = htons(2427);
	if (connect(fw->mgcp_agent.bfd.fd, (struct sockaddr *) & addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to connect to local MGCP GW. %s\n", strerror(errno));
		close(fw->mgcp_agent.bfd.fd);
		fw->mgcp_agent.bfd.fd = -1;
		return -1;
	}

	osmo_wqueue_init(&fw->mgcp_agent, 10);
	fw->mgcp_agent.bfd.data = fw;
	fw->mgcp_agent.bfd.when = BSC_FD_READ;
	fw->mgcp_agent.read_cb = mgcp_do_read;
	fw->mgcp_agent.write_cb = mgcp_do_write;

	if (osmo_fd_register(&fw->mgcp_agent.bfd) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to register BFD\n");
		close(fw->mgcp_agent.bfd.fd);
		fw->mgcp_agent.bfd.fd = -1;
		return -1;
	}

	return 0;
}

static void msc_send(struct msc_connection *fw, struct msgb *msg, int proto)
{
	if (fw->msc_link_down) {
		LOGP(DMSC, LOGL_NOTICE, "Dropping data due lack of MSC connection.\n");
		msgb_free(msg);
		return;
	}

	ipaccess_prepend_header(msg, proto);

	if (osmo_wqueue_enqueue(&fw->msc_connection, msg) != 0) {
		LOGP(DMSC, LOGL_FATAL, "Failed to queue MSG for the MSC.\n");
		msgb_free(msg);
		return;
	}
}

void msc_send_rlc(struct msc_connection *fw,
		  struct sccp_source_reference *src, struct sccp_source_reference *dst)
{
	struct msgb *msg;

	if (fw->msc_link_down) {
		LOGP(DMSC, LOGL_NOTICE, "Not releasing connection due lack of connection.\n");
		return;
	}

	msg = create_sccp_rlc(src, dst);
	if (!msg)
		return;

	msc_send(fw, msg, IPAC_PROTO_SCCP);
}

void msc_send_reset(struct msc_connection *fw)
{
	struct msgb *msg;

	if (fw->msc_link_down) {
		LOGP(DMSC, LOGL_NOTICE, "Not sending reset due lack of connection.\n");
		return;
	}

	msg = create_reset();
	if (!msg)
		return;

	msc_send(fw, msg, IPAC_PROTO_SCCP);
	msc_ping_timeout(fw);
}

static void msc_send_id_response(struct msc_connection *fw)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "id resp");
	msg->l2h = msgb_v_put(msg, IPAC_MSGT_ID_RESP);
	msgb_l16tv_put(msg, strlen(fw->token) + 1,
		       IPAC_IDTAG_UNITNAME, (uint8_t *) fw->token);

	msc_send(fw, msg, IPAC_PROTO_IPACCESS);
}

void msc_send_direct(struct msc_connection *fw, struct msgb *msg)
{
	return msc_send(fw, msg, IPAC_PROTO_SCCP);
}

struct msc_connection *msc_connection_create(struct bsc_data *bsc, int mgcp)
{
	struct msc_connection *msc;

	msc = talloc_zero(NULL, struct msc_connection);
	if (!msc) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate the MSC Connection.\n");
		return NULL;
	}

	osmo_wqueue_init(&msc->msc_connection, 100);
	msc->reconnect_timer.cb = msc_reconnect;
	msc->reconnect_timer.data = msc;
	msc->msc_connection.read_cb = ipaccess_a_fd_cb;
	msc->msc_connection.write_cb = ipaccess_write_cb;
	msc->msc_connection.bfd.data = msc;
	msc->msc_link_down = 1;

	/* handle the timeout */
	msc->ping_timeout.cb = msc_ping_timeout;
	msc->ping_timeout.data = msc;
	msc->pong_timeout.cb = msc_pong_timeout;
	msc->pong_timeout.data = msc;

	/* create MGCP port */
	if (mgcp && mgcp_create_port(msc) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Failed to bind for the MGCP port.\n");
		talloc_free(msc);
		return NULL;
	}

	llist_add_tail(&msc->entry, &bsc->mscs);
	msc->nr = bsc->num_mscs++;

	return msc;
}

struct msc_connection *msc_connection_num(struct bsc_data *bsc, int num)
{
	struct msc_connection *msc;

	llist_for_each_entry(msc, &bsc->mscs, entry)
		if (msc->nr == num)
			return msc;
	return NULL;
}

int msc_connection_start(struct msc_connection *msc)
{
	if (msc->msc_connection.bfd.fd > 0) {
		LOGP(DMSC, LOGL_ERROR,
		     "Function should not be called with active connection.\n");
		return -1;
	}

	msc_schedule_reconnect(msc);
	return 0;
}
