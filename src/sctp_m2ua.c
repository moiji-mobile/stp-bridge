/* Run M2UA over SCTP here */
/* (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <sctp_m2ua.h>
#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <counter.h>
#include <mtp_data.h>
#include <mtp_pcap.h>

#include <osmocore/talloc.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <string.h>
#include <unistd.h>

extern struct bsc_data bsc;

static void link_down(struct mtp_link *link)
{
	rate_ctr_inc(&link->ctrg->ctr[MTP_LNK_ERROR]);
	mtp_link_down(link);
}

static void m2ua_conn_destroy(struct sctp_m2ua_conn *conn)
{
	close(conn->queue.bfd.fd);
	bsc_unregister_fd(&conn->queue.bfd);
	write_queue_clear(&conn->queue);
	llist_del(&conn->entry);

	if (conn->asp_up && conn->asp_active && conn->established)
		link_down(&conn->trans->base);
	talloc_free(conn);

	#warning "Notify any other AS(P) for failover scenario"
}

static int m2ua_conn_send(struct sctp_m2ua_conn *conn,
			  struct m2ua_msg *m2ua,
			  struct sctp_sndrcvinfo *info)
{
	struct msgb *msg;
	msg = m2ua_to_msg(m2ua);
	if (!msg)
		return -1;

	/* save the OOB data in front of the message */
	msg->l2h = msg->data;
	msgb_push(msg, sizeof(*info));
	memcpy(msg->data, info, sizeof(*info));

	if (write_queue_enqueue(&conn->queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue.\n");
		msgb_free(msg);
		return -1;
	}

	return 0;
}

static int m2ua_conn_send_ntfy(struct sctp_m2ua_conn *conn,
			       struct sctp_sndrcvinfo *info)
{
	struct m2ua_msg *msg;
	uint16_t state[2];
	int rc;

	msg = m2ua_msg_alloc();
	if (!msg)
		return -1;
	msg->hdr.msg_class = M2UA_CLS_MGMT;
	msg->hdr.msg_type = M2UA_MGMT_NTFY;

	/* state change */
	state[0] = ntohs(M2UA_STP_AS_STATE_CHG);

	if (conn->asp_active)
		state[1] = ntohs(M2UA_STP_AS_ACTIVE);
	else
		state[1] = ntohs(M2UA_STP_AS_INACTIVE);

	m2ua_msg_add_data(msg, MUA_TAG_STATUS, 4, (uint8_t *) state);
	m2ua_msg_add_data(msg, MUA_TAG_ASP_IDENT, 4, conn->asp_ident);
	rc = m2ua_conn_send(conn, msg, info);
	m2ua_msg_free(msg);

	return rc;
}

static int m2ua_handle_asp_ack(struct sctp_m2ua_conn *conn,
			       struct m2ua_msg *m2ua,
			       struct sctp_sndrcvinfo *info)
{
	struct m2ua_msg_part *asp_ident;
	struct m2ua_msg *ack;

	asp_ident = m2ua_msg_find_tag(m2ua, MUA_TAG_ASP_IDENT);
	if (!asp_ident) {
		LOGP(DINP, LOGL_ERROR, "ASP UP lacks ASP IDENT\n");
		return -1;
	}
	if (asp_ident->len != 4) {
		LOGP(DINP, LOGL_ERROR, "ASP Ident needs to be four byte.\n");
		return -1;
	}

	/* TODO: Better handling for fail over is needed here */
	ack = m2ua_msg_alloc();
	if (!ack) {
		LOGP(DINP, LOGL_ERROR, "Failed to create response\n");
		return -1;
	}

	ack->hdr.msg_class = M2UA_CLS_ASPSM;
	ack->hdr.msg_type = M2UA_ASPSM_UP_ACK;
	if (m2ua_conn_send(conn, ack, info) != 0) {
		m2ua_msg_free(ack);
		return -1;
	}

	memcpy(conn->asp_ident, asp_ident->dat, 4);
	conn->asp_up = 1;

	m2ua_conn_send_ntfy(conn, info);
	m2ua_msg_free(ack);
	return 0;
}

static int m2ua_handle_asp(struct sctp_m2ua_conn *conn,
			   struct m2ua_msg *m2ua, struct sctp_sndrcvinfo *info)
{
	switch (m2ua->hdr.msg_type) {
	case M2UA_ASPSM_UP:
		m2ua_handle_asp_ack(conn, m2ua, info);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n",
			m2ua->hdr.msg_type);
		break;
	}

	return 0;
}

static int m2ua_handle_asptm_act(struct sctp_m2ua_conn *conn,
				 struct m2ua_msg *m2ua,
				 struct sctp_sndrcvinfo *info)
{
	struct m2ua_msg *ack;

	/* TODO: parse the interface identifiers. This is plural */
	ack = m2ua_msg_alloc();
	if (!ack)
		return -1;

	ack->hdr.msg_class = M2UA_CLS_ASPTM;
	ack->hdr.msg_type = M2UA_ASPTM_ACTIV_ACK;

	if (m2ua_conn_send(conn, ack, info) != 0) {
		m2ua_msg_free(ack);
		return -1;
	}

	conn->asp_active = 1;
	m2ua_conn_send_ntfy(conn, info);
	m2ua_msg_free(ack);
	return 0;
}

static int m2ua_handle_asptm(struct sctp_m2ua_conn *conn,
			     struct m2ua_msg *m2ua,
			     struct sctp_sndrcvinfo *info)
{
	switch (m2ua->hdr.msg_type) {
	case M2UA_ASPTM_ACTIV:
		m2ua_handle_asptm_act(conn, m2ua, info);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n",
			m2ua->hdr.msg_type);
		break;
	}

	return 0;
}

static int m2ua_handle_state_req(struct sctp_m2ua_conn *conn,
				 struct m2ua_msg *m2ua,
				 struct sctp_sndrcvinfo *info)
{
	struct m2ua_msg_part *ident, *state;
	struct m2ua_msg *conf;
	int interface = 0, req;

	state = m2ua_msg_find_tag(m2ua, M2UA_TAG_STATE_REQ);
	if (!state || state->len != 4) {
		LOGP(DINP, LOGL_ERROR, "Mandantory state request not present.\n");
		return -1;
	}

	ident = m2ua_msg_find_tag(m2ua, MUA_TAG_IDENT_INT);
	if (ident && ident->len == 4) {
		memcpy(&interface, ident->dat, 4);
		interface = ntohl(interface);
	}

	memcpy(&req, state->dat, 4);
	req = ntohl(req);

	switch (req) {
	case M2UA_STATUS_EMER_SET:
		conf = m2ua_msg_alloc();
		if (!conf)
			return -1;

		conf->hdr.msg_class = M2UA_CLS_MAUP;
		conf->hdr.msg_type = M2UA_MAUP_STATE_CON;
		m2ua_msg_add_data(conf, MUA_TAG_IDENT_INT, 4, (uint8_t *) &interface);
		m2ua_msg_add_data(conf, M2UA_TAG_STATE_REQ, 4, (uint8_t *) &req);
		if (m2ua_conn_send(conn, conf, info) != 0) {
			m2ua_msg_free(conf);
			return -1;
		}
		m2ua_msg_free(conf);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unknown STATE Request: %d\n", req);
		break;
	}

	return 0;
}

static int m2ua_handle_est_req(struct sctp_m2ua_conn *conn,
			       struct m2ua_msg *m2ua,
			       struct sctp_sndrcvinfo *info)
{
	struct m2ua_msg *conf;

	conf = m2ua_msg_alloc();
	if (!conf)
		return -1;

	conf->hdr.msg_class = M2UA_CLS_MAUP;
	conf->hdr.msg_type = M2UA_MAUP_EST_CON;

	if (m2ua_conn_send(conn, conf, info) != 0) {
		m2ua_msg_free(conf);
		return -1;
	}

	conn->established = 1;
	LOGP(DINP, LOGL_NOTICE, "M2UA/Link is established.\n");
	mtp_link_up(&conn->trans->base);
	m2ua_msg_free(conf);
	return 0;
}

static int m2ua_handle_rel_req(struct sctp_m2ua_conn *conn,
			       struct m2ua_msg *m2ua,
			       struct sctp_sndrcvinfo *info)
{
	struct m2ua_msg *conf;

	conf = m2ua_msg_alloc();
	if (!conf)
		return -1;

	conf->hdr.msg_class = M2UA_CLS_MAUP;
	conf->hdr.msg_type = M2UA_MAUP_REL_CON;

	if (m2ua_conn_send(conn, conf, info) != 0) {
		m2ua_msg_free(conf);
		return -1;
	}

	conn->established = 0;
	LOGP(DINP, LOGL_NOTICE, "M2UA/Link is released.\n");
	link_down(&conn->trans->base);
	m2ua_msg_free(conf);
	return 0;
}

static int m2ua_handle_data(struct sctp_m2ua_conn *conn,
			    struct m2ua_msg *m2ua,
			    struct sctp_sndrcvinfo *info)
{
	struct msgb *msg;
	struct m2ua_msg_part *data;
	struct mtp_link *link;

	data = m2ua_msg_find_tag(m2ua, M2UA_TAG_DATA);
	if (!data) {
		LOGP(DINP, LOGL_ERROR, "No DATA in DATA message.\n");
		return -1;
	}

	if (data->len > 2048) {
		LOGP(DINP, LOGL_ERROR, "TOO much data for us to handle.\n");
		return -1;
	}

	msg = msgb_alloc(2048, "m2ua-data");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate storage.\n");
		return -1;
	}

	msg->l2h = msgb_put(msg, data->len);
	memcpy(msg->l2h, data->dat, data->len);

	link = &conn->trans->base;
	if (!link->blocked) {
		mtp_handle_pcap(link, NET_IN, msg->l2h, msgb_l2len(msg));
		mtp_link_set_data(link, msg);
	}
	msgb_free(msg);

	return 0;
}

static int m2ua_handle_maup(struct sctp_m2ua_conn *conn,
			    struct m2ua_msg *m2ua,
			    struct sctp_sndrcvinfo *info)
{
	switch (m2ua->hdr.msg_type) {
	case M2UA_MAUP_STATE_REQ:
		m2ua_handle_state_req(conn, m2ua, info);
		break;
	case M2UA_MAUP_EST_REQ:
		m2ua_handle_est_req(conn, m2ua, info);
		break;
	case M2UA_MAUP_REL_REQ:
		m2ua_handle_rel_req(conn, m2ua, info);
		break;
	case M2UA_MAUP_DATA:
		m2ua_handle_data(conn, m2ua, info);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n",
			m2ua->hdr.msg_type);
		break;
	}

	return 0;
}

static int m2ua_handle_mgmt(struct sctp_m2ua_conn *conn,
			    struct m2ua_msg *m2ua, struct sctp_sndrcvinfo *info)
{
	switch (m2ua->hdr.msg_type) {
	case M2UA_MGMT_ERROR:
		LOGP(DINP, LOGL_ERROR, "We did something wrong. Error...\n");
		break;
	case M2UA_MGMT_NTFY:
		LOGP(DINP, LOGL_NOTICE, "There was a notiy.. but we should only send it.\n");
		break;
	}

	return 0;
}

static int m2ua_conn_handle(struct sctp_m2ua_conn *conn,
			    struct msgb *msg, struct sctp_sndrcvinfo *info)
{
	struct m2ua_msg *m2ua;
	m2ua = m2ua_from_msg(msg->len, msg->data);
	if (!m2ua) {
		LOGP(DINP, LOGL_ERROR, "Failed to parse the message.\n");
		return -1;
	}

	switch (m2ua->hdr.msg_class) {
	case M2UA_CLS_MGMT:
		m2ua_handle_mgmt(conn, m2ua, info);
		break;
	case M2UA_CLS_ASPSM:
		m2ua_handle_asp(conn, m2ua, info);
		break;
	case M2UA_CLS_ASPTM:
		m2ua_handle_asptm(conn, m2ua, info);
		break;
	case M2UA_CLS_MAUP:
		m2ua_handle_maup(conn, m2ua, info);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_class %d\n",
			m2ua->hdr.msg_class);
		break;
	}

	m2ua_msg_free(m2ua);
	return 0;
}

static int m2ua_conn_read(struct bsc_fd *fd)
{
	struct sockaddr_in addr;
	struct sctp_sndrcvinfo info;
	socklen_t len = sizeof(addr);
	struct msgb *msg;
	int rc;

	msg = msgb_alloc(2048, "m2ua buffer");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate buffer.\n");
		m2ua_conn_destroy(fd->data);
		return -1;
	}

	memset(&info, 0, sizeof(info));
	memset(&addr, 0, sizeof(addr));
	rc = sctp_recvmsg(fd->fd, msg->data, msg->data_len,
			  (struct sockaddr *) &addr, &len, &info, NULL);
	if (rc < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to read.\n");
		m2ua_conn_destroy(fd->data);
		return -1;
	}

	msgb_put(msg, rc);
	LOGP(DINP, LOGL_NOTICE, "Read %d on stream: %d ssn: %d assoc: %d\n",
		rc, info.sinfo_stream, info.sinfo_ssn, info.sinfo_assoc_id);
	m2ua_conn_handle(fd->data, msg, &info);
	msgb_free(msg);
	return 0;
}

static int sctp_m2ua_write(struct mtp_link *link, struct msgb *msg)
{
	struct mtp_m2ua_link *trans;
	struct sctp_m2ua_conn *conn = NULL, *tmp;
	struct sctp_sndrcvinfo info;
	struct m2ua_msg *m2ua;
	uint32_t interface;

	trans = (struct mtp_m2ua_link *) link;

	if (llist_empty(&trans->conns))
		return -1;

	llist_for_each_entry(tmp, &trans->conns, entry)
		if (tmp->established && tmp->asp_active && tmp->asp_up) {
			conn = tmp;
			break;
		}

	if (!conn) {
		LOGP(DINP, LOGL_ERROR, "No active ASP?\n");
		return -1;
	}

	m2ua = m2ua_msg_alloc();
	if (!m2ua)
		return -1;

	mtp_handle_pcap(link, NET_OUT, msg->data, msg->len);

	m2ua->hdr.msg_class = M2UA_CLS_MAUP;
	m2ua->hdr.msg_type = M2UA_MAUP_DATA;

	interface = htonl(0);
	m2ua_msg_add_data(m2ua, MUA_TAG_IDENT_INT, 4, (uint8_t *) &interface);
	m2ua_msg_add_data(m2ua, M2UA_TAG_DATA, msg->len, msg->data);

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 1;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(2);

	m2ua_conn_send(conn, m2ua, &info);
	m2ua_msg_free(m2ua);
	return 0;
}

static int m2ua_conn_write(struct bsc_fd *fd, struct msgb *msg)
{
	int ret;
	struct sctp_sndrcvinfo info;
	memcpy(&info, msg->data, sizeof(info));

	ret = sctp_send(fd->fd, msg->l2h, msgb_l2len(msg),
			&info, 0);

	if (ret != msgb_l2len(msg))
		LOGP(DINP, LOGL_ERROR, "Failed to send %d.\n", ret);

	return 0;
}

static int sctp_trans_accept(struct bsc_fd *fd, unsigned int what)
{
	struct sctp_event_subscribe events;
	struct mtp_m2ua_link *trans;
	struct sctp_m2ua_conn *conn;
	struct sockaddr_in addr;
	socklen_t len;
	int s;

	len = sizeof(addr);
	s = accept(fd->fd, (struct sockaddr *) &addr, &len);
	if (s < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to accept.\n");
		return -1;
	}

	trans = fd->data;
	if (!trans->started) {
		LOGP(DINP, LOGL_NOTICE, "The link is not started.\n");
		close(s);
		return -1;
	}

	if (!trans->base.blocked) {
		LOGP(DINP, LOGL_NOTICE, "The link is blocked.\n");
		close(s);
		return -1;
	}

	LOGP(DINP, LOGL_NOTICE, "Got a new SCTP connection.\n");
	conn = talloc_zero(fd->data, struct sctp_m2ua_conn);
	if (!conn) {
		LOGP(DINP, LOGL_ERROR, "Failed to create.\n");
		close(s);
		return -1;
	}

	conn->trans = trans;

	write_queue_init(&conn->queue, 10);
	conn->queue.bfd.fd = s;
	conn->queue.bfd.data = conn;
	conn->queue.bfd.when = BSC_FD_READ;
	conn->queue.read_cb = m2ua_conn_read;
	conn->queue.write_cb = m2ua_conn_write;

	if (bsc_register_fd(&conn->queue.bfd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register.\n");
		close(s);
		talloc_free(conn);
		return -1;
	}

	memset(&events, 0, sizeof(events));
	events.sctp_data_io_event = 1;
	setsockopt(s, SOL_SCTP, SCTP_EVENTS, &events, sizeof(events));

	llist_add_tail(&conn->entry, &trans->conns);
	return 0;
}

static int sctp_m2ua_dummy(struct mtp_link *link)
{
	return 0;
}

static int sctp_m2ua_start(struct mtp_link *link)
{
	struct mtp_m2ua_link *trans = (struct mtp_m2ua_link *) link;

	trans->started = 1;
	return 0;
}

static int sctp_m2ua_reset(struct mtp_link *link)
{
	struct sctp_m2ua_conn *conn, *tmp;
	struct mtp_m2ua_link *transp = (struct mtp_m2ua_link *) link;

	llist_for_each_entry_safe(conn, tmp, &transp->conns, entry)
		m2ua_conn_destroy(conn);

	return 0;
}

struct mtp_m2ua_link *sctp_m2ua_transp_create(const char *ip, int port)
{
	int sctp;
	struct sockaddr_in addr;
	struct mtp_m2ua_link *trans;

	sctp = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (!sctp) {
		LOGP(DINP, LOGL_ERROR, "Failed to create socket.\n");
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	if (bind(sctp, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to bind.\n");
		close(sctp);
		return NULL;
	}

	if (listen(sctp, 1) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to listen.\n");
		close(sctp);
		return NULL;
	}

	int on = 1;
	setsockopt(sctp, SOL_SCTP, 112, &on, sizeof(on));

	trans = talloc_zero(NULL, struct mtp_m2ua_link);
	if (!trans) {
		LOGP(DINP, LOGL_ERROR, "Remove the talloc.\n");
		close(sctp);
		return NULL;
	}

	trans->base.shutdown = sctp_m2ua_reset;
	trans->base.clear_queue = sctp_m2ua_dummy;
	trans->base.reset = sctp_m2ua_reset;
	trans->base.start = sctp_m2ua_start;
	trans->base.write = sctp_m2ua_write;

	trans->bsc.fd = sctp;
	trans->bsc.data = trans;
	trans->bsc.cb = sctp_trans_accept;
	trans->bsc.when = BSC_FD_READ;

	if (bsc_register_fd(&trans->bsc) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register the fd.\n");
		talloc_free(trans);
		close(sctp);
		return NULL;
	}

	INIT_LLIST_HEAD(&trans->conns);
	return trans;
}

