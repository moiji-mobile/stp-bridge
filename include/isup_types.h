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

#ifndef isup_types_h
#define isup_types_h

#include <stdint.h>
#include <endian.h>

struct msgb;
struct mtp_link;

/* This is from Table 4/Q.763 */
#define ISUP_MSG_GRS	0x17
#define ISUP_MSG_GRA	0x29

struct isup_msg_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t cic   : 12,
		 spare :  4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t spare :  4,
		 cic   : 12;
#endif
	uint8_t  msg_type;
	uint8_t  data[0];
} __attribute__((packed));

struct isup_msg_grs {
	uint8_t  pointer_int;
};

int mtp_link_forward_isup(struct mtp_link *link, struct msgb *msg, int sls);

int isup_parse_grs(const uint8_t *data, uint8_t length);

#endif
