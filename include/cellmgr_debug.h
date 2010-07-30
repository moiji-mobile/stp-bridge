#ifndef CELLMGR_DEBUG_H
#define CELLMGR_DEBUG_H

#define DEBUG
#include <osmocore/logging.h>

/* Debuag Areas of the code */
enum {
	DINP,
	DMSC,
	DSCCP,
	DMGCP,
};

extern const struct log_info log_info;

#endif
