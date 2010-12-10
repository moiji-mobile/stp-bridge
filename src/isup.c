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

#include <isup_types.h>
#include <cellmgr_debug.h>

/* this message contains the range */
int isup_parse_grs(const uint8_t *data, uint8_t in_length)
{
	uint8_t ptr;
	uint8_t length;

	if (in_length > 3) {
		LOGP(DISUP, LOGL_ERROR, "This needs three bytes.\n");
		return -1;	
	}

	ptr = data[0];
	if (1 + ptr > in_length) {
		LOGP(DISUP, LOGL_ERROR, "Pointing outside the packet.\n");
		return -1;
	}

	length = data[0 + ptr];

	if (1 + ptr + 1 > in_length) {
		LOGP(DISUP, LOGL_ERROR, "No space for the data.\n");
		return -1;
	}

	return data[0 + ptr + 1];
}

