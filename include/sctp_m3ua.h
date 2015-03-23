/*
 * Represet M3UA client (and later server) links
 */
#pragma once

#include "mtp_data.h"

#include <netinet/in.h>

struct mtp_m3ua_client_link {
	struct mtp_link *base;

	char *source;
	struct sockaddr_in local;

	char *dest;
	struct sockaddr_in remote;
	int link_index;
	int routing_context;
};

struct mtp_m3ua_client_link *mtp_m3ua_client_link_init(struct mtp_link *link);
