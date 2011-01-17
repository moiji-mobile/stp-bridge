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

#ifndef sctp_m2ua_h
#define sctp_m2ua_h

#include "mtp_data.h"

#include <osmocom/m2ua/m2ua_msg.h>
#include <osmocore/write_queue.h>

#include <netinet/in.h>
#include <netinet/sctp.h>

struct sctp_m2ua_conn;
struct mtp_link;

/**
 * Drive M2UA over a SCTP link. Right now we have no
 * real concept for failover and such for the link.
 */
struct mtp_m2ua_link {
	struct mtp_link base;

	int started;
	struct llist_head conns;
	struct bsc_fd bsc;
};

/*
 * One ASP that can be active or such.
 */
struct sctp_m2ua_conn {
	struct llist_head entry;
	uint8_t asp_ident[4];
	int asp_up;
	int asp_active;
	int established;

	struct write_queue queue;
	struct mtp_m2ua_link *trans;
};

struct mtp_m2ua_link *sctp_m2ua_transp_create(const char *ip, int port);

#endif
