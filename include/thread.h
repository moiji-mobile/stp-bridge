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
#ifndef thread_h
#define thread_h

#include <laf0rge1/linuxlist.h>
#include <laf0rge1/select.h>

#include <pthread.h>

/**
 * routines for dealing with threads
 */
struct thread_notifier {
	struct bsc_fd bfd;

	int no_write;
	int fd[2];

	pthread_mutex_t guard;
	struct llist_head *main_head;
	struct llist_head *thread_head;

	struct llist_head __head1;
	struct llist_head __head2;
};

struct thread_notifier *thread_notifier_alloc();

/**
 * atomically swap two llist heads. This can be used
 * to have two queues of data and then swap them for
 * processing.
 */
void thread_swap(struct thread_notifier *);

void thread_safe_add(struct thread_notifier *, struct llist_head *_new);

void thread_init(void);

#endif
