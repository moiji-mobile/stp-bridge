/*
 * Represet M3UA client (and later server) links
 */
#pragma once

#include "mtp_data.h"

#include <osmocom/core/write_queue.h>

#include <netinet/in.h>

struct mtp_m3ua_client_link {
	struct mtp_link *base;

	struct osmo_wqueue queue;
	struct osmo_timer_list connect_timer;

	char *source;
	struct sockaddr_in local;

	char *dest;
	struct sockaddr_in remote;
	int link_index;
	int routing_context;


	/* state of the link */
	int aspsm_active;
	int asptm_active;
};

struct mtp_m3ua_client_link *mtp_m3ua_client_link_init(struct mtp_link *link);
