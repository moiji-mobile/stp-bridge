/*
 * (C) 2010-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2012 by On-Waves
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

	printf("Testing CIC parsing.\n");

	hdr = (struct isup_msg_hdr *) isup_grs;
	ASSERT(isup_cic_to_local(hdr), 3);
	ASSERT(hdr->msg_type, ISUP_MSG_GRS);
}

static void test_grs_parsing()
{
	static const uint8_t isup_grs[] = {3, 0, 23, 1, 1, 28};
	struct isup_msg_hdr *hdr;
	int range;

	printf("Testing GRS parsing.\n");

	hdr = (struct isup_msg_hdr *) isup_grs;
	range = isup_parse_status(&hdr->data[0], 3);

	ASSERT(isup_cic_to_local(hdr), 3);
	ASSERT(hdr->msg_type, ISUP_MSG_GRS);
	ASSERT(range, 28);
}

static void test_gra_parsing()
{
	static const uint8_t isup_gra[] = {
					0x02, 0x00, 0x29, 0x01,
					0x05, 0x1d, 0x00, 0x00,
					0xff, 0x3f };
	struct isup_msg_hdr *hdr;
	int range;

	printf("Testing GRA parsing.\n");
	hdr = (struct isup_msg_hdr *) isup_gra;
	range = isup_parse_status(&hdr->data[0], 3);
	ASSERT(isup_cic_to_local(hdr), 2);
	ASSERT(hdr->msg_type, ISUP_MSG_GRA);
	ASSERT(range, 29);
}

static void test_rsc_parsing()
{
	static const uint8_t isup_rsc[] = {0x01, 0x00, 0x012};
	struct isup_msg_hdr *hdr;

	printf("Testing RSC parsing.\n");
	hdr = (struct isup_msg_hdr *) isup_rsc;
	ASSERT(isup_cic_to_local(hdr), 1);
	ASSERT(hdr->msg_type, ISUP_MSG_RSC);
}

int main(int argc, char **argv)
{
	test_cic_parsing();
	test_grs_parsing();
	test_gra_parsing();
	test_rsc_parsing();

	printf("All tests passed.\n");
	return 0;
}

/* stubs */
int mtp_link_set_submit_isup_data() {return -1;}
int mtp_link_set_forward_isup(struct mtp_link_set *s, struct msgb *m, int l) { abort(); }
