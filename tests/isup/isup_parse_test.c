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

static void test_grs_parsing()
{
	static const uint8_t isup_grs[] = {3, 0, 23, 1, 1, 28};
	struct isup_msg_hdr *hdr;
	int range;

	hdr = (struct isup_msg_hdr *) isup_grs;
	range = isup_parse_grs(&hdr->data[0], 3);

	ASSERT(range, 28);
}

int main(int argc, char **argv)
{
	test_cic_parsing();
	test_grs_parsing();

	printf("All tests passed.\n");
	return 0;
}

/* stubs */
int mtp_link_set_submit_isup_data() {return -1;}
int mtp_link_set_forward_isup(struct mtp_link_set *s, struct msgb *m, int l) { abort(); }
