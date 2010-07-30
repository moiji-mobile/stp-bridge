/* mgcp_ss7 helper coder */
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

#ifndef mgcp_ss7_h
#define mgcp_ss7_h

#include <osmocore/timer.h>
#include <osmocore/write_queue.h>

#include "thread.h"


struct mgcp_ss7_endpoint;
struct mgcp_ss7 {
	struct mgcp_config *cfg;
	struct write_queue mgcp_fd;
	struct msgb *mgcp_msg;

	struct mgcp_ss7_endpoint *mgw_end;

	/* timer */
	struct timer_list poll_timer;

	/* thread handling */
	struct thread_notifier *cmd_queue;
	pthread_t thread;
};

enum {
	MGCP_SS7_MUTE_STATUS,
	MGCP_SS7_ALLOCATE,
	MGCP_SS7_DELETE,
	MGCP_SS7_SHUTDOWN,
};

struct mgcp_ss7_cmd {
	struct llist_head entry;
	uint8_t type;
	uint32_t port;
	uint32_t param;
};

void mgcp_ss7_exec(struct mgcp_ss7 *mgcp, uint8_t type, uint32_t port, uint32_t param);

struct mgcp_ss7 *mgcp_ss7_init(int endpoints, const char *local_ip, const char *mgw_ip, int base_port, int payload);
void mgcp_ss7_reset(struct mgcp_ss7 *mgcp);
void mgcp_ss7_free(struct mgcp_ss7 *mgcp);

#endif
