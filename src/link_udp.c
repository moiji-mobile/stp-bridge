/* Implementation of the C7 UDP link */
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

#define OSMO_CB_LI(msg) msg->cb[0]

static struct link_data *find_link(struct bsc_data *bsc, int link_index)
{
	struct link_data *link;

	llist_for_each_entry(link, &bsc->links, entry)
		if (link->link_index == link_index)
			return link;

	return NULL;
}

static int udp_write_cb(struct bsc_fd *fd, struct msgb *msg)
{
	struct bsc_data *bsc;
	struct link_data *link;
	int rc;

	bsc = (struct bsc_data *) fd->data;

	link = find_link(bsc, OSMO_CB_LI(msg));
	if (!link) {
		LOGP(DINP, LOGL_ERROR, "No link_data for %lu\n", OSMO_CB_LI(msg));
		return -1;
	}

	LOGP(DINP, LOGL_DEBUG, "Sending MSU: %s\n", hexdump(msg->data, msg->len));
	if (link->pcap_fd >= 0)
		mtp_pcap_write_msu(link->pcap_fd, msg->l2h, msgb_l2len(msg));

	/* the assumption is we have connected the socket to the remote */
	rc = sendto(fd->fd, msg->data, msg->len, 0,
		     (struct sockaddr *) &link->udp.remote, sizeof(link->udp.remote));
	if (rc != msg->len) {
		LOGP(DINP, LOGL_ERROR, "Failed to write msg to socket: %d\n", rc);
		return -1;
	}

	return 0;
}

static int udp_read_cb(struct bsc_fd *fd)
{
	struct bsc_data *bsc;
	struct link_data *link;
	struct udp_data_hdr *hdr;
	struct msgb *msg;
	int rc;
	unsigned int length;

	msg = msgb_alloc_headroom(4096, 128, "UDP datagram");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate memory.\n");
		return -1;
	}
	    

	bsc = (struct bsc_data *) fd->data;
	rc = read(fd->fd, msg->data, 2096);
	if (rc < sizeof(*hdr)) {
		LOGP(DINP, LOGL_ERROR, "Failed to read at least size of the header: %d\n", rc);
		rc = -1;
		goto exit;
	}

	hdr = (struct udp_data_hdr *) msgb_put(msg, sizeof(*hdr));

	link = find_link(bsc, ntohs(hdr->data_link_index));
	if (!link) {
		LOGP(DINP, LOGL_ERROR, "Failed to find a link.\n");
		rc = -1;
		goto exit;
	}

	/* throw away data as the link is down */
	if (link->the_link->available == 0) {
		LOGP(DINP, LOGL_ERROR, "The link is down. Not forwarding.\n");
		rc = 0;
		goto exit;
	}


	if (hdr->data_type == UDP_DATA_RETR_COMPL || hdr->data_type == UDP_DATA_RETR_IMPOS) {
		LOGP(DINP, LOGL_ERROR, "Link retrieval done. Restarting the link.\n");
		bsc_link_down(link);
		bsc_link_up(link);
		goto exit;
	} else if (hdr->data_type > UDP_DATA_MSU_PRIO_3) {
		LOGP(DINP, LOGL_ERROR, "Link failure. retrieved message.\n");
		bsc_link_down(link);
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
	mtp_link_data(link->the_link, msg);

exit:
	msgb_free(msg);
	return rc;
}

static int udp_link_dummy(struct link_data *link)
{
	/* nothing todo */
	return 0;
}

static void do_start(void *_data)
{
	struct link_data *link = (struct link_data *) _data;

	link->forced_down = 0;
	snmp_mtp_activate(link->udp.session, link->link_index);
	bsc_link_up(link);
}

static int udp_link_reset(struct link_data *link)
{
	LOGP(DINP, LOGL_NOTICE, "Will restart SLTM transmission in %d seconds.\n",
	     link->udp.reset_timeout);
	snmp_mtp_deactivate(link->udp.session, link->link_index);
	bsc_link_down(link);

	/* restart the link in 90 seconds... to force a timeout on the BSC */
	link->link_activate.cb = do_start;
	link->link_activate.data = link;
	bsc_schedule_timer(&link->link_activate, link->udp.reset_timeout, 0);
	return 0;
}

static int udp_link_write(struct link_data *link, struct msgb *msg)
{
	struct udp_data_hdr *hdr;

	hdr = (struct udp_data_hdr *) msgb_push(msg, sizeof(*hdr));
	hdr->format_type = UDP_FORMAT_SIMPLE_UDP;
	hdr->data_type = UDP_DATA_MSU_PRIO_0;
	hdr->data_link_index = htons(link->link_index);
	hdr->user_context = 0;
	hdr->data_length = htonl(msgb_l2len(msg));

	OSMO_CB_LI(msg) = link->link_index;

	if (write_queue_enqueue(&link->bsc->udp_write_queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue msg.\n");
		msgb_free(msg);
		return -1;
	}

	return 0;
}

static int udp_link_start(struct link_data *link)
{
	LOGP(DINP, LOGL_NOTICE, "UDP input is ready.\n");
	do_start(link);
	return 0;
}

int link_udp_network_init(struct bsc_data *bsc)
{
	struct sockaddr_in addr;
	int fd;
	int on;

	write_queue_init(&bsc->udp_write_queue, 100);

	/* socket creation */
	bsc->udp_write_queue.bfd.data = bsc;
	bsc->udp_write_queue.bfd.when = BSC_FD_READ;
	bsc->udp_write_queue.read_cb = udp_read_cb;
	bsc->udp_write_queue.write_cb = udp_write_cb;

	bsc->udp_write_queue.bfd.fd = fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to create UDP socket.\n");
		return -1;
	}

	on = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(bsc->src_port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind UDP socket");
		close(fd);
		return -1;
	}

	/* now connect the socket to the remote */

	if (bsc_register_fd(&bsc->udp_write_queue.bfd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register BFD.\n");
		close(fd);
		return -1;
	}

	return 0;
}

int link_udp_init(struct link_data *link, const char *remote, int remote_port)
{
	/* function table */
	link->shutdown = udp_link_dummy;
	link->clear_queue = udp_link_dummy;

	link->reset = udp_link_reset;
	link->start = udp_link_start;
	link->write = udp_link_write;

	memset(&link->udp.remote, 0, sizeof(link->udp.remote));
	link->udp.remote.sin_family = AF_INET;
	link->udp.remote.sin_port = htons(remote_port);
	inet_aton(remote, &link->udp.remote.sin_addr);

	return 0;
}
