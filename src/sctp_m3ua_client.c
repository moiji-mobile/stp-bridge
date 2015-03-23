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

#include <osmocom/core/talloc.h>

#include <netinet/sctp.h>

#include <unistd.h>

#define SCTP_PPID_M3UA 3

#define notImplemented()	\
		LOGP(DINP, LOGL_NOTICE, "%s not implemented.\n", __func__)

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
	notImplemented();
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
}

static int m3ua_write(struct mtp_link *mtp_link, struct msgb *msg)
{
	notImplemented();
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
	return lnk;
}
