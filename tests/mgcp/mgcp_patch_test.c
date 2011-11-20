/*
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by On-Waves
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
 */

#include <mgcp_patch.h>
#include <ss7_application.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char mgcp_in[] =
	"MDCX 23213 14@mgw MGCP 1.0\r\n"
	"C: 4a84ad5d25f\r\n"
	"I: %d\r\n"
	"L: p:20, a:GSM-EFR, nt:IN\r\n"
	"M: recvonly\r\n\r\n"
	"v=0\r\n"
	"o=- 258696477 0 IN IP4 172.16.1.107\r\n"
	"s=-\r\n"
	"c=IN IP4 172.16.1.107\r\n"
	"t=0 0\r\n"
	"m=audio 6666 RTP/AVP 127\r\n"
	"a=rtpmap:127 GSM-EFR/8000/1\r\n"
	"a=ptime:20\r\n"
	"a=recvonly\r\n"
	"m=image 4402 udptl t38\r\n"
	"a=T38FaxVersion:0\r\n"
	"a=T38MaxBitRate:14400\r\n";

static const char mgcp_out[] =
	"MDCX 23213 14@foo2 MGCP 1.0\r\n"
	"C: 4a84ad5d25f\r\n"
	"I: %d\r\n"
	"L: p:20, a:GSM-EFR, nt:IN\r\n"
	"M: recvonly\r\n\r\n"
	"v=0\r\n"
	"o=- 258696477 0 IN IP4 172.16.1.107\r\n"
	"s=-\r\n"
	"c=IN IP4 172.16.1.107\r\n"
	"t=0 0\r\n"
	"m=audio 6666 RTP/AVP 127\r\n"
	"a=rtpmap:127 GSM-EFR/8000/1\r\n"
	"a=ptime:20\r\n"
	"a=recvonly\r\n"
	"m=image 4402 udptl t38\r\n"
	"a=T38FaxVersion:0\r\n"
	"a=T38MaxBitRate:14400\r\n";

#define ASSERT(a, cmp, b, text) 		\
	if (!((a) cmp (b))) {			\
		fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, text);	\
		abort();			\
	}

static void test_endp_name_rewriting()
{
	struct ss7_application app;

	printf("Test Endpoint Name rewriting.\n");

	memset(&app, 0, sizeof(app));
	app.mgcp_domain_name = "foo2";

	/* prepare */
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "test");
	msg->l2h = msgb_put(msg, strlen(mgcp_in));
	memcpy(msg->l2h, mgcp_in, msgb_l2len(msg));

	/* patch it now */
	struct msgb *msg_out = mgcp_patch(&app, msg);
	msg_out->l2h[msgb_l2len(msg_out)] = '\0';
	printf("Want : '%s'\n", mgcp_out);
	printf("Outpu: '%s'\n", (const char *) msg_out->l2h);
	printf("%s\n", osmo_hexdump((const uint8_t *) mgcp_out, strlen(mgcp_out)));
	printf("%s\n", osmo_hexdump(msg_out->l2h, msgb_l2len(msg_out)));
	ASSERT(msg_out, !=, msg, "msg should not be the same");

	ASSERT(msgb_l2len(msg_out), ==, strlen(mgcp_out), "Output size wrong");
	ASSERT(strcmp((const char *)msg_out->l2h, mgcp_out), ==, 0, "Text don't match");
}

int main(int argc, char **argv)
{
	test_endp_name_rewriting();

	printf("All tests passed.\n");
	return 0;
}
