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
#include <string.h>
#include <bsc_data.h>

#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/m3ua_types.h>
#include <osmocom/mtp/mtp_level3.h>

#include <osmocom/core/talloc.h>

#include <netinet/sctp.h>

#include <unistd.h>

#define SCTP_PPID_M3UA 3

#define notImplemented()	\
		LOGP(DINP, LOGL_NOTICE, "%s not implemented.\n", __func__)


/*
 * State machine code
 */
static void m3ua_handle_aspsm(struct mtp_m3ua_client_link *link, struct xua_msg *msg);
static void m3ua_handle_asptm(struct mtp_m3ua_client_link *link, struct xua_msg *msg);
static void m3ua_handle_trans(struct mtp_m3ua_client_link *link, struct xua_msg *msg);
static void m3ua_send_daud(struct mtp_m3ua_client_link *link, uint32_t pc);
static void m3ua_send_aspup(struct mtp_m3ua_client_link *link);
static void m3ua_send_aspac(struct mtp_m3ua_client_link *link);

/*
 * boilerplate
 */
static int m3ua_shutdown(struct mtp_link *mtp_link);
static void m3ua_start(void *data);

static void schedule_restart(struct mtp_m3ua_client_link *link)
{
	link->connect_timer.data = link;
	link->connect_timer.cb = m3ua_start;
	osmo_timer_schedule(&link->connect_timer, 1, 0);
}

static void fail_link(struct mtp_m3ua_client_link *link)
{
	/* We need to fail the link */
	m3ua_shutdown(link->base);
	mtp_link_down(link->base);
	schedule_restart(link);
}

static int m3ua_conn_handle(struct mtp_m3ua_client_link *link,
				struct msgb *msg, struct sctp_sndrcvinfo *info)
{
	struct xua_msg *m3ua;
	m3ua = xua_from_msg(M3UA_VERSION, msg->len, msg->data);
	if (!m3ua) {
		LOGP(DINP, LOGL_ERROR, "Failed to parse the message.\n");
		return -1;
	}

	switch (m3ua->hdr.msg_class) {
	case M3UA_CLS_ASPSM:
		m3ua_handle_aspsm(link, m3ua);
		break;
	case M3UA_CLS_ASPTM:
		m3ua_handle_asptm(link, m3ua);
		break;
	case M3UA_CLS_TRANS:
		m3ua_handle_trans(link, m3ua);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_class %d\n",
			m3ua->hdr.msg_class);
		break;
	}

	xua_msg_free(m3ua);
	return 0;
}

static int m3ua_conn_write(struct osmo_fd *fd, struct msgb *msg)
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

static int m3ua_conn_send(struct mtp_m3ua_client_link *link,
			  struct xua_msg *m3ua,
			  struct sctp_sndrcvinfo *info)
{
	struct msgb *msg;
	msg = xua_to_msg(M3UA_VERSION, m3ua);
	if (!msg)
		return -1;

	/* save the OOB data in front of the message */
	msg->l2h = msg->data;
	msgb_push(msg, sizeof(*info));
	memcpy(msg->data, info, sizeof(*info));

	if (osmo_wqueue_enqueue(&link->queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue.\n");
		msgb_free(msg);
		return -1;
	}

	return 0;
}

static int m3ua_conn_read(struct osmo_fd *fd)
{
	struct sockaddr_in addr;
	struct sctp_sndrcvinfo info;
	socklen_t len = sizeof(addr);
	struct mtp_m3ua_client_link *link = fd->data;
	struct msgb *msg;
	int rc;

	msg = msgb_alloc(2048, "m3ua buffer");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate buffer.\n");
		fail_link(link);
		return -1;
	}

	memset(&info, 0, sizeof(info));
	memset(&addr, 0, sizeof(addr));
	rc = sctp_recvmsg(fd->fd, msg->data, msg->data_len,
			  (struct sockaddr *) &addr, &len, &info, NULL);
	if (rc <= 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to read.\n");
		msgb_free(msg);
		fail_link(link);
		return -1;
	}

	if (ntohl(info.sinfo_ppid) != SCTP_PPID_M3UA) {
		LOGP(DINP, LOGL_ERROR, "Only M3UA is allowed on this socket: %d\n",
			ntohl(info.sinfo_ppid));
		msgb_free(msg);
		return -1;
	}

	msgb_put(msg, rc);
	LOGP(DINP, LOGL_DEBUG, "Read %d on stream: %d ssn: %d assoc: %d\n",
		rc, info.sinfo_stream, info.sinfo_ssn, info.sinfo_assoc_id);
	m3ua_conn_handle(link, msg, &info);
	msgb_free(msg);
	return 0;
}

static void m3ua_start(void *data)
{
	int sctp, ret;
	struct sockaddr_in loc_addr, rem_addr;
	struct mtp_m3ua_client_link *link = data;
	struct sctp_event_subscribe events;

	sctp = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (!sctp) {
		LOGP(DINP, LOGL_ERROR, "Failed to create socket.\n");
		return fail_link(link);
	}

	memset(&events, 0, sizeof(events));
	events.sctp_data_io_event = 1;
	ret = setsockopt(sctp, SOL_SCTP, SCTP_EVENTS, &events, sizeof(events));
	if (ret != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enable SCTP Events. Closing socket.\n");
		close(sctp);
		return fail_link(link);
	}

	loc_addr = link->local;
	loc_addr.sin_family = AF_INET;
	if (bind(sctp, (struct sockaddr *) &loc_addr, sizeof(loc_addr)) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to bind.\n");
		close(sctp);
		return fail_link(link);
	}

	rem_addr = link->remote;
	rem_addr.sin_family = AF_INET;
	if (connect(sctp, (struct sockaddr *) &rem_addr, sizeof(rem_addr)) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to connect\n");
		close(sctp);
		return fail_link(link);
	}

	link->queue.bfd.fd = sctp;
	link->queue.bfd.data = link;
	link->queue.bfd.when = BSC_FD_READ;
	link->queue.read_cb = m3ua_conn_read;
	link->queue.write_cb = m3ua_conn_write;

	if (osmo_fd_register(&link->queue.bfd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register fd\n");
		close(sctp);
		return fail_link(link);
	}

	/* begin the messages for bring-up */
	m3ua_send_aspup(link);
}

static int m3ua_write(struct mtp_link *mtp_link, struct msgb *msg)
{
	struct mtp_m3ua_client_link *link = mtp_link->data;
	struct sctp_sndrcvinfo info;
	struct xua_msg *m3ua;
	struct mtp_level_3_hdr *mtp_hdr;
	struct m3ua_protocol_data proto_data;
	uint8_t *proto_start;

	if (!link->asptm_active) {
		LOGP(DINP, LOGL_ERROR, "ASP not ready  for %d/%s of %d/%s.\n",
			mtp_link->nr, mtp_link->name, mtp_link->set->nr,
			mtp_link->set->name);
		goto clean;
	}

	/*
	 * TODO.. we could enhance the structure of mtp_link to
	 * have function pointers for operations like SLTM instead
	 * of doing what we do here.
	 * The entire m3ua episode (code + reading the spec) had a
	 * budget of < 2 man days so the amount of architecture changes
	 * we can do.
	 */

	/* TODO.. need to terminate MTPL3 locally... */

	/* TODO.. extract MTP information.. */
	mtp_hdr = (struct mtp_level_3_hdr *) msg->l2h;
	switch (mtp_hdr->ser_ind) {
	case MTP_SI_MNT_SNM_MSG:
	case MTP_SI_MNT_REG_MSG:
		LOGP(DINP, LOGL_ERROR,
			"Dropping SNM/REG message %d\n", mtp_hdr->ser_ind);
		goto clean;
		break;
	case MTP_SI_MNT_ISUP:
	case MTP_SI_MNT_SCCP:
	default:
		memset(&proto_data, 0, sizeof(proto_data));
		proto_data.opc = htonl(MTP_READ_OPC(mtp_hdr->addr));
		proto_data.dpc = htonl(MTP_READ_DPC(mtp_hdr->addr));
		proto_data.sls = MTP_LINK_SLS(mtp_hdr->addr);
		proto_data.si = mtp_hdr->ser_ind;
		proto_data.ni = mtp_link->set->ni;

		msg->l3h = mtp_hdr->data;
		msgb_pull_to_l3(msg);
		proto_start = msgb_push(msg, sizeof(proto_data));
		memcpy(proto_start, &proto_data, sizeof(proto_data));
		break;
	};

	m3ua = xua_msg_alloc();
	if (!m3ua)
		goto clean;

	mtp_handle_pcap(mtp_link, NET_OUT, msg->data, msg->len);

	m3ua->hdr.msg_class = M3UA_CLS_TRANS;
	m3ua->hdr.msg_type = M3UA_TRANS_DATA;

	/*
	 * Modify the data...to create a true protocol data..
	 */
	xua_msg_add_data(m3ua, M3UA_TAG_PROTO_DATA, msg->len, msg->data);

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 1;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	m3ua_conn_send(link, m3ua, &info);
	xua_msg_free(m3ua);

clean:
	msgb_free(msg);
	return 0;
}

static int m3ua_shutdown(struct mtp_link *mtp_link)
{
	struct mtp_m3ua_client_link *link = mtp_link->data;

	if (link->queue.bfd.fd >= 0) {
		osmo_fd_unregister(&link->queue.bfd);
		close(link->queue.bfd.fd);
		link->queue.bfd.fd = -1;
	}
	osmo_wqueue_clear(&link->queue);
	link->aspsm_active = 0;
	link->asptm_active = 0;
	return 0;
}

static int m3ua_reset(struct mtp_link *mtp_link)
{
	struct mtp_m3ua_client_link *link = mtp_link->data;

	/* stop things in case they run.. */
	m3ua_shutdown(mtp_link);
	schedule_restart(link);
	return 0;
}

static int m3ua_clear_queue(struct mtp_link *mtp_link)
{
	struct mtp_m3ua_client_link *link = mtp_link->data;
	osmo_wqueue_clear(&link->queue);
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

	osmo_wqueue_init(&lnk->queue, 10);
	lnk->queue.bfd.fd = -1;
	lnk->traffic_mode = 2;
	return lnk;
}


/*
 * asp handling
 */
static void m3ua_send_aspup(struct mtp_m3ua_client_link *link)
{
	struct sctp_sndrcvinfo info;
	struct xua_msg *aspup;
	uint32_t asp_ident;

	aspup = xua_msg_alloc();
	if (!aspup) {
		fail_link(link);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 0;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	aspup->hdr.msg_class = M3UA_CLS_ASPSM;
	aspup->hdr.msg_type = M3UA_ASPSM_UP;

	asp_ident = htonl(link->link_index);
	xua_msg_add_data(aspup, MUA_TAG_ASP_IDENT, 4, (uint8_t *) &asp_ident);

	m3ua_conn_send(link, aspup, &info);
	xua_msg_free(aspup);
}

static void m3ua_send_aspac(struct mtp_m3ua_client_link *link)
{
	struct sctp_sndrcvinfo info;
	struct xua_msg *aspac;
	uint32_t routing_ctx;
	uint32_t traffic_mode;

	aspac = xua_msg_alloc();
	if (!aspac) {
		fail_link(link);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 0;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	aspac->hdr.msg_class = M3UA_CLS_ASPTM;
	aspac->hdr.msg_type = M3UA_ASPTM_ACTIV;

	traffic_mode = htonl(link->traffic_mode);
	xua_msg_add_data(aspac, 11, 4, (uint8_t *) &traffic_mode);

	routing_ctx = htonl(link->routing_context);
	xua_msg_add_data(aspac, MUA_TAG_ROUTING_CTX, 4, (uint8_t *) &routing_ctx);

	m3ua_conn_send(link, aspac, &info);
	xua_msg_free(aspac);
}

static void m3ua_send_daud(struct mtp_m3ua_client_link *link, uint32_t dpc)
{
	struct sctp_sndrcvinfo info;
	struct xua_msg *daud;
	uint32_t routing_ctx;

	daud = xua_msg_alloc();
	if (!daud) {
		fail_link(link);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 0;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	daud->hdr.msg_class = M3UA_CLS_SSNM;
	daud->hdr.msg_type = M3UA_SSNM_DAUD;

	routing_ctx = htonl(link->routing_context);
	xua_msg_add_data(daud, MUA_TAG_ROUTING_CTX, 4, (uint8_t *) &routing_ctx);

	dpc = htonl(dpc);
	xua_msg_add_data(daud, MUA_TAG_AFF_PC, 4, (uint8_t *) &dpc);

	m3ua_conn_send(link, daud, &info);
	xua_msg_free(daud);
}

static void m3ua_handle_aspsm(struct mtp_m3ua_client_link *link, struct xua_msg *m3ua)
{
	switch (m3ua->hdr.msg_type) {
	case M3UA_ASPSM_UP_ACK:
		LOGP(DINP, LOGL_NOTICE, "Received ASP_UP_ACK.. sending ASPAC\n");
		link->aspsm_active = 1;
		m3ua_send_aspac(link);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n",
			m3ua->hdr.msg_type);
		break;
	}
}

static void m3ua_handle_asptm(struct mtp_m3ua_client_link *link, struct xua_msg *m3ua)
{
	switch (m3ua->hdr.msg_type) {
	case M3UA_ASPTM_ACTIV_ACK:
		LOGP(DINP, LOGL_NOTICE, "Received ASPAC_ACK.. taking link up\n");
		link->asptm_active = 1;
		mtp_link_up(link->base);
		m3ua_send_daud(link, link->base->set->dpc);
		if (link->base->set->sccp_dpc != -1)
			m3ua_send_daud(link, link->base->set->sccp_dpc);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n",
			m3ua->hdr.msg_type);
		break;
	}
}

static void m3ua_handle_trans(struct mtp_m3ua_client_link *link, struct xua_msg *m3ua)
{
	struct msgb *msg;
	struct xua_msg_part *data;
	struct mtp_link *mtp_link;
	struct m3ua_protocol_data *proto;
	struct mtp_level_3_hdr *mtp_hdr;
	uint32_t opc, dpc;
	uint8_t sls, si;

	mtp_link = link->base;

	/* ignore everything if the link is blocked */
	if (mtp_link->blocked)
		return;

	if (m3ua->hdr.msg_type != M3UA_TRANS_DATA) {
		LOGP(DINP, LOGL_ERROR, "msg_type(%d) is not known. Ignoring\n",
			m3ua->hdr.msg_type);
		return;
	}

	data = xua_msg_find_tag(m3ua, M3UA_TAG_PROTO_DATA);
	if (!data) {
		LOGP(DINP, LOGL_ERROR, "No PROTO_DATA in DATA message.\n");
		return;
	}

	if (data->len > 2048) {
		LOGP(DINP, LOGL_ERROR, "TOO much data for us to handle.\n");
		return;
	}

	if (data->len < sizeof(struct m3ua_protocol_data)) {
		LOGP(DINP, LOGL_ERROR, "Too little data..\n");
		return;
	}

	msg = msgb_alloc(2048, "m3ua-data");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate storage.\n");
		return;
	}

	msg->l2h = msgb_put(msg, data->len);
	memcpy(msg->l2h, data->dat, data->len);

	proto = (struct m3ua_protocol_data *) msg->l2h;
	opc = ntohl(proto->opc);
	dpc = ntohl(proto->dpc);
	sls = proto->sls;
	si = proto->si;
	LOGP(DINP, LOGL_DEBUG, "Got data for OPC(%d)/DPC(%d)/SLS(%d) len(%d)\n",
		opc, dpc, sls, msgb_l2len(msg) - sizeof(*proto));


	/* put a MTP3 header in front */
	msg->l3h = proto->data;
	msgb_pull_to_l3(msg);
	msg->l2h = msgb_push(msg, sizeof(*mtp_hdr));
	mtp_hdr = (struct mtp_level_3_hdr *) msg->l2h;
	mtp_hdr->ser_ind = si;
	mtp_hdr->addr = MTP_ADDR(sls % 16, dpc, opc);

	mtp_handle_pcap(mtp_link, NET_IN, msg->l2h, msgb_l2len(msg));
	mtp_link_set_data(mtp_link, msg);
	msgb_free(msg);
}
