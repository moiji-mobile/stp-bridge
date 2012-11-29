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

#include <mgcp/mgcp.h>
#include <mgcp/mgcp_internal.h>
#include <mgcp_patch.h>
#include <ss7_application.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>

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

#define CRCX	 "CRCX 2 1@mgw MGCP 1.0\r\n"	\
		 "M: sendrecv\r\n"		\
		 "C: 2\r\n"			\
		 "\r\n"				\
		 "v=0\r\n"			\
		 "c=IN IP4 123.12.12.123\r\n"	\
		 "m=audio 5904 RTP/AVP 97\r\n"	\
		 "a=rtpmap:97 GSM-EFR/8000\r\n"

#define DLCX	 "DLCX 7 1@mgw MGCP 1.0\r\n"	\
		 "C: 2\r\n"

#define RQNT	 "RQNT 186908780 1@mgw MGCP 1.0\r\n"	\
		 "X: B244F267488\r\n"			\
		 "S: D/9\r\n"

#define RQNT2	 "RQNT 186908780 1@mgw MGCP 1.0\r\n"	\
		 "X: ADD4F26746F\r\n"			\
		 "R: D/[0-9#*](N), G/ft, fxr/t38\r\n"

#define RQNT_RET "200 186908780 OK\r\n"

#define ASSERT(a, cmp, b, text) 		\
	if (!((a) cmp (b))) {			\
		fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, text);	\
		abort();			\
	}

static struct msgb *create_msg(const char *str)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	int len = sprintf((char *)msg->data, str);
	msg->l2h = msgb_put(msg, len);
	return msg;
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

static int rqnt_cb(struct mgcp_endpoint *endp, char _tone, const char *data)
{
	ptrdiff_t tone = _tone;
	endp->cfg->data = (void *) tone;
	return 0;
}

static void test_rqnt_cb(void)
{
	struct mgcp_config *cfg;
	struct mgcp_trunk_config *tcfg;
	struct msgb *inp, *msg;

	cfg = mgcp_config_alloc();
	cfg->rqnt_cb = rqnt_cb;

	tcfg = mgcp_vtrunk_alloc(cfg, "mgw");
	tcfg->number_endpoints = 64;
	mgcp_endpoints_allocate(tcfg);

	inp = create_msg(CRCX);
	msgb_free(mgcp_handle_message(cfg, inp));
	msgb_free(inp);

	/* send the RQNT and check for the CB */
	inp = create_msg(RQNT);
	msg = mgcp_handle_message(cfg, inp);
	if (strncmp((const char *) msg->l2h, "200", 3) != 0) {
		printf("FAILED: message is not 200. '%s'\n", msg->l2h);
		abort();
	}

	if (cfg->data != (void *) '9') {
		printf("FAILED: callback not called: %p\n", cfg->data);
		abort();
	}

	msgb_free(msg);
	msgb_free(inp);

	inp = create_msg(DLCX);
	msgb_free(mgcp_handle_message(cfg, inp));
	msgb_free(inp);
	talloc_free(cfg);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);

	test_endp_name_rewriting();
	test_rqnt_cb();

	printf("All tests passed.\n");
	return 0;
}
