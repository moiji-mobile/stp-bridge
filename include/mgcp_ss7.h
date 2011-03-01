/* mgcp_ss7 helper coder */
/*
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
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

#ifndef mgcp_ss7_h
#define mgcp_ss7_h

#include <osmocore/timer.h>
#include <osmocore/write_queue.h>

#include <osmocom/vty/command.h>

#include "thread.h"

struct mgcp_ss7 {
	struct mgcp_config *cfg;
	struct write_queue mgcp_fd;
	struct msgb *mgcp_msg;

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
};

struct mgcp_ss7_cmd {
	struct llist_head entry;
	uint8_t type;
	struct mgcp_endpoint *endp;
	uint32_t param;
};

void mgcp_ss7_reset(struct mgcp_ss7 *mgcp);

void mgcp_mgw_vty_init();

#endif
