/* MSC related stuff... */
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

#include <bsc_data.h>
#include <bsc_ussd.h>
#include <bss_patch.h>
#include <bssap_sccp.h>
#include <ipaccess.h>
#include <mtp_data.h>
#include <cellmgr_debug.h>

#include <osmocore/tlv.h>
#include <osmocore/utils.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define RECONNECT_TIME		10, 0
#define NAT_MUX 0xfc

static void msc_send_id_response(struct bsc_data *bsc);
static void msc_send(struct bsc_data *bsc, struct msgb *msg, int proto);
static void msc_schedule_reconnect(struct bsc_data *bsc);

void mtp_link_slta_recv(struct mtp_link *link)
{
	struct msgb *msg;
	unsigned int sls;

	while (!llist_empty(&link->pending_msgs)) {
		msg = msgb_dequeue(&link->pending_msgs);
		sls = (unsigned int) msg->l3h;

		if (mtp_link_submit_sccp_data(link, sls, msg->l2h, msgb_l2len(msg)) != 0)
			LOGP(DMSC, LOGL_ERROR, "Could not forward SCCP message.\n");

		msgb_free(msg);
	}
}

int send_or_queue_bsc_msg(struct mtp_link *link, int sls, struct msgb *msg)
{
	if (link->sltm_pending) {
		LOGP(DMSC, LOGL_NOTICE, "Queueing msg for pending SLTM.\n");
		msg->l3h = (uint8_t *) sls;
		msgb_enqueue(&link->pending_msgs, msg);
		return 1;
	}

	if (mtp_link_submit_sccp_data(link, sls, msg->l2h, msgb_l2len(msg)) != 0)
		LOGP(DMSC, LOGL_ERROR, "Could not forward SCCP message.\n");
	return 0;
}


void msc_clear_queue(struct bsc_data *data)
{
	struct msgb *msg;

	LOGP(DMSC, LOGL_NOTICE, "Clearing the MSC to BSC queue.\n");
	while (!llist_empty(&data->link.the_link->pending_msgs)) {
		msg = msgb_dequeue(&data->link.the_link->pending_msgs);
		msgb_free(msg);
	}
}

void msc_close_connection(struct bsc_data *bsc)
{
	struct bsc_fd *bfd = &bsc->msc_connection.bfd;

	close(bfd->fd);
	bsc_unregister_fd(bfd);
	bfd->fd = -1;
	bsc->msc_link_down = 1;
	release_bsc_resources(bsc);
	bsc_del_timer(&bsc->ping_timeout);
	bsc_del_timer(&bsc->pong_timeout);
	bsc_del_timer(&bsc->msc_timeout);
	msc_schedule_reconnect(bsc);
}

static void msc_connect_timeout(void *_bsc_data)
{
	struct bsc_data *bsc_data = _bsc_data;

	LOGP(DMSC, LOGL_ERROR, "Timeout on the MSC connection.\n");
	msc_close_connection(bsc_data);
}

static void msc_pong_timeout(void *_bsc_data)
{
	struct bsc_data *bsc_data = _bsc_data;
	LOGP(DMSC, LOGL_ERROR, "MSC didn't respond to ping. Closing.\n");
	msc_close_connection(bsc_data);
}

static void send_ping(struct bsc_data *bsc)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "ping");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create PING.\n");
		return;
	}

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;

	msc_send(bsc, msg, IPAC_PROTO_IPACCESS);
}

static void msc_ping_timeout(void *_bsc_data)
{
	struct bsc_data *bsc_data = _bsc_data;

	if (bsc_data->ping_time < 0)
		return;

	send_ping(bsc_data);

	/* send another ping in 20 seconds */
	bsc_schedule_timer(&bsc_data->ping_timeout, bsc_data->ping_time, 0);

	/* also start a pong timer */
	bsc_schedule_timer(&bsc_data->pong_timeout, bsc_data->pong_time, 0);
}

/*
 * callback with IP access data
 */
static int ipaccess_a_fd_cb(struct bsc_fd *bfd)
{
	int error;
	struct ipaccess_head *hh;
	struct mtp_link *link;
	struct bsc_data *bsc;
	struct msgb *msg;

	msg = ipaccess_read_msg(bfd, &error);

	bsc = (struct bsc_data *) bfd->data;

	if (!msg) {
		if (error == 0)
			fprintf(stderr, "The connection to the MSC was lost, exiting\n");
		else
			fprintf(stderr, "Error in the IPA stream.\n");

		msc_close_connection(bsc);
		return -1;
	}

	LOGP(DMSC, LOGL_DEBUG, "From MSC: %s proto: %d\n", hexdump(msg->data, msg->len), msg->l2h[0]);

	/* handle base message handling */
	hh = (struct ipaccess_head *) msg->data;
	ipaccess_rcvmsg_base(msg, bfd);

	link = bsc->link.the_link;

	/* initialize the networking. This includes sending a GSM08.08 message */
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		if (bsc->first_contact) {
			LOGP(DMSC, LOGL_NOTICE, "Connected to MSC. Sending reset.\n");
			bsc_del_timer(&bsc->msc_timeout);
			bsc->first_contact = 0;
			bsc->msc_link_down = 0;
			msc_send_reset(bsc);
		}
		if (msg->l2h[0] == IPAC_MSGT_ID_GET && bsc->token) {
			msc_send_id_response(bsc);
		} else if (msg->l2h[0] == IPAC_MSGT_PONG) {
			bsc_del_timer(&bsc->pong_timeout);
		}
	} else if (hh->proto == IPAC_PROTO_SCCP) {
		struct sccp_parse_result result;
		int rc;
		rc = bss_patch_filter_msg(msg, &result);

		if (rc == BSS_FILTER_RESET_ACK) {
			LOGP(DMSC, LOGL_NOTICE, "Filtering reset ack from the MSC\n");
		} else if (rc == BSS_FILTER_RLSD) {
			LOGP(DMSC, LOGL_DEBUG, "Filtering RLSD from the MSC\n");
			update_con_state(rc, &result, msg, 1, 0);
		} else if (rc == BSS_FILTER_RLC) {
			/* if we receive this we have forwarded a RLSD to the network */
			LOGP(DMSC, LOGL_ERROR, "RLC from the network. BAD!\n");
		} else if (rc == BSS_FILTER_CLEAR_COMPL) {
			LOGP(DMSC, LOGL_ERROR, "Clear Complete from the network.\n");
		} else if (link->sccp_up) {
			unsigned int sls;

			update_con_state(rc, &result, msg, 1, 0);
			sls = sls_for_src_ref(result.destination_local_reference);

			/* Check for Location Update Accept */
			bsc_ussd_handle_in_msg(bsc, &result, msg);

			/* patch a possible PC */
			bss_rewrite_header_to_bsc(msg, link->opc, link->dpc);

			/* we can not forward it right now */
			if (send_or_queue_bsc_msg(link, sls, msg) == 1)
				return 0;

		}
	} else if (hh->proto == NAT_MUX) {
		mgcp_forward(bsc, msg->l2h, msgb_l2len(msg));
	} else {
		LOGP(DMSC, LOGL_ERROR, "Unknown IPA proto 0x%x\n", hh->proto);
	}

	msgb_free(msg);
	return 0;
}

static int ipaccess_write_cb(struct bsc_fd *fd, struct msgb *msg)
{
	int rc;

	LOGP(DMSC, LOGL_DEBUG, "Sending to MSC: %s\n", hexdump(msg->data, msg->len));
	rc = write(fd->fd, msg->data, msg->len);
	if (rc != msg->len)
		LOGP(DMSC, LOGL_ERROR, "Could not write to MSC.\n");

	return rc;
}

/* called in the case of a non blocking connect */
static int msc_connection_connect(struct bsc_fd *fd, unsigned int what)
{
	int rc;
	int val;
	socklen_t len = sizeof(val);
	struct bsc_data *bsc;

	bsc = (struct bsc_data *) fd->data;

	if (fd != &bsc->msc_connection.bfd) {
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
	fd->cb = write_queue_bfd_cb;
	fd->when = BSC_FD_READ;
	if (!llist_empty(&bsc->msc_connection.msg_queue))
		fd->when |= BSC_FD_WRITE;
	return 0;

error:
	msc_close_connection(bsc);
	return -1;
}

static int setnonblocking(struct bsc_fd *fd)
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

static int connect_to_msc(struct bsc_fd *fd, const char *ip, int port, int tos)
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
		fd->cb = write_queue_bfd_cb;
	}

	ret = bsc_register_fd(fd);
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
	struct bsc_data *bsc = (struct bsc_data *) _data;

	bsc_del_timer(&bsc->reconnect_timer);
	bsc->first_contact = 1;

	rc = connect_to_msc(&bsc->msc_connection.bfd, bsc->msc_address, 5000, bsc->msc_ip_dscp);
	if (rc < 0) {
		fprintf(stderr, "Opening the MSC connection failed. Trying again\n");
		bsc_schedule_timer(&bsc->reconnect_timer, RECONNECT_TIME);
		return;
	}

	bsc->msc_timeout.cb = msc_connect_timeout;
	bsc->msc_timeout.data = bsc;
	bsc_schedule_timer(&bsc->msc_timeout, bsc->msc_time, 0);
}

static void msc_schedule_reconnect(struct bsc_data *bsc)
{
	bsc_schedule_timer(&bsc->reconnect_timer, RECONNECT_TIME);
}

/*
 * mgcp forwarding is below
 */
static int mgcp_do_write(struct bsc_fd *fd, struct msgb *msg)
{
	int ret;

	LOGP(DMGCP, LOGL_DEBUG, "Sending msg to MGCP GW size: %u\n", msg->len);

	ret = write(fd->fd, msg->data, msg->len);
	if (ret != msg->len)
		LOGP(DMGCP, LOGL_ERROR, "Failed to forward message to MGCP GW (%s).\n", strerror(errno));

	return ret;
}

static int mgcp_do_read(struct bsc_fd *fd)
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

void mgcp_forward(struct bsc_data *bsc, const uint8_t *data, unsigned int length)
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
	if (write_queue_enqueue(&bsc->mgcp_agent, mgcp) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Could not queue message to MGCP GW.\n");
		msgb_free(mgcp);
	}
}

static int mgcp_create_port(struct bsc_data *bsc)
{
	int on;
	struct sockaddr_in addr;

	bsc->mgcp_agent.bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (bsc->mgcp_agent.bfd.fd < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to create UDP socket errno: %d\n", errno);
		return -1;
	}

	on = 1;
	setsockopt(bsc->mgcp_agent.bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* try to bind the socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(bsc->mgcp_agent.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to bind to any port.\n");
		close(bsc->mgcp_agent.bfd.fd);
		bsc->mgcp_agent.bfd.fd = -1;
		return -1;
	}

	/* connect to the remote */
	addr.sin_port = htons(2427);
	if (connect(bsc->mgcp_agent.bfd.fd, (struct sockaddr *) & addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to connect to local MGCP GW. %s\n", strerror(errno));
		close(bsc->mgcp_agent.bfd.fd);
		bsc->mgcp_agent.bfd.fd = -1;
		return -1;
	}

	write_queue_init(&bsc->mgcp_agent, 10);
	bsc->mgcp_agent.bfd.data = bsc;
	bsc->mgcp_agent.bfd.when = BSC_FD_READ;
	bsc->mgcp_agent.read_cb = mgcp_do_read;
	bsc->mgcp_agent.write_cb = mgcp_do_write;

	if (bsc_register_fd(&bsc->mgcp_agent.bfd) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to register BFD\n");
		close(bsc->mgcp_agent.bfd.fd);
		bsc->mgcp_agent.bfd.fd = -1;
		return -1;
	}

	return 0;
}

int msc_init(struct bsc_data *bsc)
{
	write_queue_init(&bsc->msc_connection, 100);
	bsc->reconnect_timer.cb = msc_reconnect;
	bsc->reconnect_timer.data = bsc;
	bsc->msc_connection.read_cb = ipaccess_a_fd_cb;
	bsc->msc_connection.write_cb = ipaccess_write_cb;
	bsc->msc_connection.bfd.data = bsc;
	bsc->msc_link_down = 1;

	/* handle the timeout */
	bsc->ping_timeout.cb = msc_ping_timeout;
	bsc->ping_timeout.data = bsc;
	bsc->pong_timeout.cb = msc_pong_timeout;
	bsc->pong_timeout.data = bsc;

	/* create MGCP port */
	if (mgcp_create_port(bsc) != 0)
		return -1;

	/* now connect to the BSC */
	msc_schedule_reconnect(bsc);
	return 0;
}

static void msc_send(struct bsc_data *bsc, struct msgb *msg, int proto)
{
	if (bsc->msc_link_down) {
		LOGP(DMSC, LOGL_NOTICE, "Dropping data due lack of MSC connection.\n");
		msgb_free(msg);
		return;
	}

	ipaccess_prepend_header(msg, proto);

	if (write_queue_enqueue(&bsc->msc_connection, msg) != 0) {
		LOGP(DMSC, LOGL_FATAL, "Failed to queue MSG for the MSC.\n");
		msgb_free(msg);
		return;
	}
}

void msc_send_rlc(struct bsc_data *bsc,
		  struct sccp_source_reference *src, struct sccp_source_reference *dst)
{
	struct msgb *msg;

	msg = create_sccp_rlc(src, dst);
	if (!msg)
		return;

	msc_send(bsc, msg, IPAC_PROTO_SCCP);
}

void msc_send_reset(struct bsc_data *bsc)
{
	struct msgb *msg;

	msg = create_reset();
	if (!msg)
		return;

	msc_send(bsc, msg, IPAC_PROTO_SCCP);
	msc_ping_timeout(bsc);
}

static void msc_send_id_response(struct bsc_data *bsc)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "id resp");
	msg->l2h = msgb_v_put(msg, IPAC_MSGT_ID_RESP);
	msgb_l16tv_put(msg, strlen(bsc->token) + 1,
		       IPAC_IDTAG_UNITNAME, (uint8_t *) bsc->token);

	msc_send(bsc, msg, IPAC_PROTO_IPACCESS);
}

void msc_send_msg(struct bsc_data *bsc, int rc, struct sccp_parse_result *result, struct msgb *_msg)
{
	struct msgb *msg;

	if (bsc->msc_connection.bfd.fd < 0) {
		LOGP(DMSC, LOGL_ERROR, "No connection to the MSC. dropping\n");
		return;
	}

	bsc_ussd_handle_out_msg(bsc, result, _msg);

	msg = msgb_alloc_headroom(4096, 128, "SCCP to MSC");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to alloc MSC msg.\n");
		return;
	}

	bss_rewrite_header_for_msc(rc, msg, _msg, result);
	msc_send(bsc, msg, IPAC_PROTO_SCCP);
}
