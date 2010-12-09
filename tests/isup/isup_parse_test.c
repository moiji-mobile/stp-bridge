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

#include <stdlib.h>
#include <stdio.h>

#define ASSERT(got,want) \
	if (got != want) { \
		fprintf(stderr, "Values should be the same 0x%x 0x%x at %s:%d\n", \
			got, want, __FILE__, __LINE__); \
		abort(); \
	}

static void test_cic_parsing()
{
	static const uint8_t isup_grs[] = {3, 0, 23, 1, 1, 28};
	struct isup_msg_hdr *hdr;

	hdr = (struct isup_msg_hdr *) isup_grs;
	ASSERT(hdr->cic, 3);
	ASSERT(hdr->msg_type, ISUP_MSG_GRS);
}

int main(int argc, char **argv)
{
	test_cic_parsing();
	return 0;
}
