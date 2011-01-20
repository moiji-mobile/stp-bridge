/* Implementation of the C7 UDP link */
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

#include <bsc_data.h>
#include <udp_input.h>
#include <mtp_data.h>
#include <mtp_pcap.h>
#include <snmp_mtp.h>
#include <cellmgr_debug.h>

#include <osmocore/talloc.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <unistd.h>

static int udp_write_cb(struct bsc_fd *fd, struct msgb *msg)
{
	struct mtp_udp_link *link;
	int rc;

	link = fd->data;

	LOGP(DINP, LOGL_DEBUG, "Sending MSU: %s\n", hexdump(msg->data, msg->len));
	if (link->base.pcap_fd >= 0)
		mtp_pcap_write_msu(link->base.pcap_fd, msg->l2h, msgb_l2len(msg));

	/* the assumption is we have connected the socket to the remote */
	rc = sendto(fd->fd, msg->data, msg->len, 0,
		     (struct sockaddr *) &link->remote, sizeof(link->remote));
	if (rc != msg->len) {
		LOGP(DINP, LOGL_ERROR, "Failed to write msg to socket: %d\n", rc);
		return -1;
	}

	return 0;
}

static int udp_read_cb(struct bsc_fd *fd)
{
	struct mtp_link *link;
	struct udp_data_hdr *hdr;
	struct msgb *msg;
	int rc;
	unsigned int length;

	msg = msgb_alloc_headroom(4096, 128, "UDP datagram");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate memory.\n");
		return -1;
	}
	    

	link = (struct mtp_link *) fd->data;
	rc = read(fd->fd, msg->data, 2096);
	if (rc < sizeof(*hdr)) {
		LOGP(DINP, LOGL_ERROR, "Failed to read at least size of the header: %d\n", rc);
		rc = -1;
		goto exit;
	}

	/* throw away data as the link is down */
	if (link->set->available == 0) {
		LOGP(DINP, LOGL_ERROR, "The link is down. Not forwarding.\n");
		rc = 0;
		goto exit;
	}

	hdr = (struct udp_data_hdr *) msgb_put(msg, sizeof(*hdr));

	if (hdr->data_type == UDP_DATA_RETR_COMPL || hdr->data_type == UDP_DATA_RETR_IMPOS) {
		LOGP(DINP, LOGL_ERROR, "Link retrieval done. Restarting the link.\n");
		mtp_link_down(link);
		mtp_link_up(link);
		goto exit;
	} else if (hdr->data_type > UDP_DATA_MSU_PRIO_3) {
		LOGP(DINP, LOGL_ERROR, "Link failure. retrieved message.\n");
		mtp_link_down(link);
		goto exit;
	}

	length = ntohl(hdr->data_length);
	if (length + sizeof(*hdr) > (unsigned int) rc) {
		LOGP(DINP, LOGL_ERROR, "The MSU payload does not fit: %u + %u > %d \n",
		     length, sizeof(*hdr), rc);
		rc = -1;
		goto exit;
	}

	msg->l2h = msgb_put(msg, length);

	LOGP(DINP, LOGL_DEBUG, "MSU data on: %p data %s.\n", link, hexdump(msg->data, msg->len));
	if (link->pcap_fd >= 0)
		mtp_pcap_write_msu(link->pcap_fd, msg->l2h, msgb_l2len(msg));
	mtp_link_set_data(link, msg);

exit:
	msgb_free(msg);
	return rc;
}

static int udp_link_dummy(struct mtp_link *link)
{
	/* nothing todo */
	return 0;
}

static void do_start(void *_data)
{
	struct mtp_udp_link *link = (struct mtp_udp_link *) _data;

	snmp_mtp_activate(link->session, link->link_index);
	mtp_link_up(&link->base);
}

static int udp_link_reset(struct mtp_link *link)
{
	struct mtp_udp_link *ulnk;

	ulnk = (struct mtp_udp_link *) link;

	LOGP(DINP, LOGL_NOTICE, "Will restart SLTM transmission in %d seconds.\n",
	     ulnk->reset_timeout);

	snmp_mtp_deactivate(ulnk->session, ulnk->link_index);
	mtp_link_down(link);

	/* restart the link in 90 seconds... to force a timeout on the BSC */
	link->link_activate.cb = do_start;
	link->link_activate.data = link;
	bsc_schedule_timer(&link->link_activate, ulnk->reset_timeout, 0);
	return 0;
}

static int udp_link_write(struct mtp_link *link, struct msgb *msg)
{
	struct mtp_udp_link *ulnk;
	struct udp_data_hdr *hdr;

	ulnk = (struct mtp_udp_link *) link;

	hdr = (struct udp_data_hdr *) msgb_push(msg, sizeof(*hdr));
	hdr->format_type = UDP_FORMAT_SIMPLE_UDP;
	hdr->data_type = UDP_DATA_MSU_PRIO_0;
	hdr->data_link_index = htons(ulnk->link_index);
	hdr->user_context = 0;
	hdr->data_length = htonl(msgb_l2len(msg));

	if (write_queue_enqueue(&ulnk->write_queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue msg.\n");
		msgb_free(msg);
		return -1;
	}

	return 0;
}

static int udp_link_start(struct mtp_link *link)
{
	LOGP(DINP, LOGL_NOTICE, "UDP input is ready.\n");
	do_start(link);
	return 0;
}

int link_udp_init(struct mtp_udp_link *link, int src_port, const char *remote, int remote_port)
{
	struct sockaddr_in addr;
	int fd;
	int on;

	write_queue_init(&link->write_queue, 100);

	/* function table */
	link->base.shutdown = udp_link_dummy;
	link->base.clear_queue = udp_link_dummy;

	link->base.reset = udp_link_reset;
	link->base.start = udp_link_start;
	link->base.write = udp_link_write;

	/* socket creation */
	link->write_queue.bfd.data = link;
	link->write_queue.bfd.when = BSC_FD_READ;
	link->write_queue.read_cb = udp_read_cb;
	link->write_queue.write_cb = udp_write_cb;

	link->write_queue.bfd.fd = fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to create UDP socket.\n");
		return -1;
	}

	on = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(src_port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind UDP socket");
		close(fd);
		return -1;
	}

	/* now connect the socket to the remote */
	memset(&link->remote, 0, sizeof(link->remote));
	link->remote.sin_family = AF_INET;
	link->remote.sin_port = htons(remote_port);
	inet_aton(remote, &link->remote.sin_addr);

	if (bsc_register_fd(&link->write_queue.bfd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register BFD.\n");
		close(fd);
		return -1;
	}

	return 0;
}
