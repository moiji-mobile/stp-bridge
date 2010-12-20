/* MTP layer3 main handling code */
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
#include <mtp_data.h>
#include <mtp_level3.h>
#include <cellmgr_debug.h>
#include <isup_types.h>

#include <osmocore/talloc.h>

#include <osmocom/sccp/sccp.h>

#include <arpa/inet.h>

#include <string.h>

static void *tall_mtp_ctx = NULL;

static int mtp_int_submit(struct mtp_link *link, int pc, int sls, int type, const uint8_t *data, unsigned int length);

static struct msgb *mtp_msg_alloc(struct mtp_link *link)
{
	struct mtp_level_3_hdr *hdr;
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "mtp-msg");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate mtp msg\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*hdr));
	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	hdr->addr = MTP_ADDR(0x0, link->dpc, link->opc);
	hdr->ni = link->ni;
	hdr->spare = link->spare;
	return msg;
}

static struct msgb *mtp_create_sltm(struct mtp_link *link)
{
	const uint8_t test_ptrn[14] = { 'G', 'S', 'M', 'M', 'M', 'S', };
	struct mtp_level_3_hdr *hdr;
	struct mtp_level_3_mng *mng;
	struct msgb *msg = mtp_msg_alloc(link);
	uint8_t *data;
	if (!msg)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	hdr->ser_ind = MTP_SI_MNT_REG_MSG;

	mng = (struct mtp_level_3_mng *) msgb_put(msg, sizeof(*mng));
	mng->cmn.h0 = MTP_TST_MSG_GRP;
	mng->cmn.h1 = MTP_TST_MSG_SLTM;
	mng->length = ARRAY_SIZE(test_ptrn);

	data = msgb_put(msg, ARRAY_SIZE(test_ptrn));
	memcpy(data, test_ptrn, ARRAY_SIZE(test_ptrn));

	/* remember the last tst ptrn... once we have some */
	memcpy(link->test_ptrn, test_ptrn, ARRAY_SIZE(test_ptrn));

	return msg;
}

static struct msgb *mtp_create_slta(struct mtp_link *link, struct mtp_level_3_mng *in_mng, int l3_len)
{
	struct mtp_level_3_hdr *hdr;
	struct mtp_level_3_mng *mng;
	struct msgb *out = mtp_msg_alloc(link);

	if (!out)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) out->l2h;
	hdr->ser_ind = MTP_SI_MNT_REG_MSG;
	mng = (struct mtp_level_3_mng *) msgb_put(out, sizeof(*mng));
	mng->cmn.h0 = MTP_TST_MSG_GRP;
	mng->cmn.h1 = MTP_TST_MSG_SLTA;
	mng->length =  l3_len - 2;
	msgb_put(out, mng->length);
	memcpy(mng->data, in_mng->data, mng->length);

	return out;
}

static struct msgb *mtp_tfp_alloc(struct mtp_link *link, int apoc)
{
	struct mtp_level_3_hdr *hdr;
	struct mtp_level_3_prohib *prb;
	struct msgb *out = mtp_msg_alloc(link);

	if (!out)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) out->l2h;
	hdr->ser_ind = MTP_SI_MNT_SNM_MSG;
	prb = (struct mtp_level_3_prohib *) msgb_put(out, sizeof(*prb));
	prb->cmn.h0 = MTP_PROHIBIT_MSG_GRP;
	prb->cmn.h1 = MTP_PROHIBIT_MSG_SIG;
	prb->apoc = MTP_MAKE_APOC(apoc);
	return out;
}

static struct msgb *mtp_tra_alloc(struct mtp_link *link)
{
	struct mtp_level_3_hdr *hdr;
	struct mtp_level_3_cmn *cmn;
	struct msgb *out = mtp_msg_alloc(link);

	if (!out)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) out->l2h;
	hdr->ser_ind = MTP_SI_MNT_SNM_MSG;
	cmn = (struct mtp_level_3_cmn *) msgb_put(out, sizeof(*cmn));
	cmn->h0 = MTP_TRF_RESTR_MSG_GRP;
	cmn->h1 = MTP_RESTR_MSG_ALLWED;
	return out;
}

static struct msgb *mtp_sccp_alloc_scmg(struct mtp_link *link,
					int type, int assn, int sls)
{
	struct sccp_data_unitdata *udt;
	struct sccp_con_ctrl_prt_mgt *prt;
	struct mtp_level_3_hdr *hdr;
	uint8_t *data;


	struct msgb *out = mtp_msg_alloc(link);

	if (!out)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) out->l2h;
	hdr->ser_ind = MTP_SI_MNT_SCCP;

	/* this appears to be round robin or such.. */
	hdr->addr = MTP_ADDR(sls % 16, link->dpc, link->sccp_opc);

	/* generate the UDT message... libsccp does not offer formating yet */
	udt = (struct sccp_data_unitdata *) msgb_put(out, sizeof(*udt));
	udt->type = SCCP_MSG_TYPE_UDT;
	udt->proto_class = SCCP_PROTOCOL_CLASS_0;
	udt->variable_called = 3;
	udt->variable_calling = 5;
	udt->variable_data = 7;

	/* put the called and calling address. It is LV */
	data = msgb_put(out, 2 + 1);
	data[0] = 2;
	data[1] = 0x42;
	data[2] = 0x1;

	data = msgb_put(out, 2 + 1);
	data[0] = 2;
	data[1] = 0x42;
	data[2] = 0x1;

	data = msgb_put(out, 1);
	data[0] = sizeof(*prt);

	prt = (struct sccp_con_ctrl_prt_mgt *) msgb_put(out, sizeof(*prt));
	prt->sst = type;
	prt->assn = assn;
	prt->apoc = MTP_MAKE_APOC(link->opc);
	prt->mul_ind = 0;

	return out;
}

void mtp_link_init(void)
{
	tall_mtp_ctx = talloc_named_const(NULL, 1, "mtp-link");
}

static void mtp_send_sltm(struct mtp_link *link)
{
	struct msgb *msg;

	link->sltm_pending = 1;
	msg = mtp_create_sltm(link);
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate SLTM.\n");
		return;
	}

	mtp_link_submit(link, msg);
}

static void mtp_sltm_t1_timeout(void *_link)
{
	struct mtp_link *link = (struct mtp_link *) _link;

	if (link->slta_misses == 0) {
		LOGP(DINP, LOGL_ERROR, "No SLTM response. Retrying. Link: %p\n", link);
		++link->slta_misses;
		mtp_send_sltm(link);
		bsc_schedule_timer(&link->t1_timer, MTP_T1);
	} else {
		LOGP(DINP, LOGL_ERROR, "Two missing SLTAs. Restart link: %p\n", link);
		link->sccp_up = 0;
		link->running = 0;
		bsc_del_timer(&link->t2_timer);
		mtp_link_sccp_down(link);
		mtp_link_restart(link);
	}
}

static void mtp_sltm_t2_timeout(void *_link)
{
	struct mtp_link *link = (struct mtp_link *) _link;

	if (!link->running) {
		LOGP(DINP, LOGL_INFO, "Not restarting SLTM timer on link: %p\n", link);
		return;
	}

	link->slta_misses = 0;
	mtp_send_sltm(link);

	bsc_schedule_timer(&link->t1_timer, MTP_T1);

	if (link->sltm_once && link->was_up)
		LOGP(DINP, LOGL_INFO, "Not sending SLTM again as configured.\n");
	else
		bsc_schedule_timer(&link->t2_timer, MTP_T2);
}

static void mtp_delayed_start(void *link)
{
	mtp_sltm_t2_timeout(link);
}

struct mtp_link *mtp_link_alloc(void)
{
	struct mtp_link *link;

	link = talloc_zero(tall_mtp_ctx, struct mtp_link);
	if (!link)
		return NULL;

	link->ni = MTP_NI_NATION_NET;
	link->t1_timer.data = link;
	link->t1_timer.cb = mtp_sltm_t1_timeout;
	link->t2_timer.data = link;
	link->t2_timer.cb = mtp_sltm_t2_timeout;
	link->delay_timer.data = link;
	link->delay_timer.cb = mtp_delayed_start;
	return link;
}

void mtp_link_stop(struct mtp_link *link)
{
	bsc_del_timer(&link->t1_timer);
	bsc_del_timer(&link->t2_timer);
	bsc_del_timer(&link->delay_timer);
	link->sccp_up = 0;
	link->running = 0;
	link->sltm_pending = 0;

	mtp_link_sccp_down(link);
}

void mtp_link_reset(struct mtp_link *link)
{
	mtp_link_stop(link);
	link->running = 1;
	bsc_schedule_timer(&link->delay_timer, START_DELAY);
}

static int mtp_link_sign_msg(struct mtp_link *link, struct mtp_level_3_hdr *hdr, int l3_len)
{
	struct msgb *msg;
	struct mtp_level_3_cmn *cmn;
	uint16_t *apc;

	if (hdr->ni != link->ni || l3_len < 1) {
		LOGP(DINP, LOGL_ERROR, "Unhandled data (ni: %d len: %d)\n",
		     hdr->ni, l3_len);
		return -1;
	}

	cmn = (struct mtp_level_3_cmn *) &hdr->data[0];
	LOGP(DINP, LOGL_DEBUG, "reg msg: h0: 0x%x h1: 0x%x\n",
             cmn->h0, cmn->h1);

	switch (cmn->h0) {
	case MTP_TRF_RESTR_MSG_GRP:
		switch (cmn->h1) {
		case MTP_RESTR_MSG_ALLWED:
			LOGP(DINP, LOGL_INFO, "Received Restart Allowed. SST could be next: %p\n", link);
			link->sccp_up = 0;
			mtp_link_sccp_down(link);

			msg = mtp_tfp_alloc(link, 0);
			if (!msg)
				return -1;
			mtp_link_submit(link, msg);

			msg = mtp_tra_alloc(link);
			if (!msg)
				return -1;

			mtp_link_submit(link, msg);
			link->sccp_up = 1;
			link->was_up = 1;
			LOGP(DINP, LOGL_INFO, "SCCP traffic allowed. %p\n", link);
			return 0;
			break;
		}
		break;
	case MTP_PROHIBIT_MSG_GRP:
		switch (cmn->h1) {
		case MTP_PROHIBIT_MSG_SIG:
			if (l3_len < 3) {
				LOGP(DINP, LOGL_ERROR, "TFP is too short.\n");
				return -1;
			}

			apc = (uint16_t *) &hdr->data[1];
			LOGP(DINP, LOGL_INFO,
			     "TFP for the affected point code: %d\n", *apc);
			return 0;
			break;
		}
		break;
	}

	LOGP(DINP, LOGL_ERROR, "Unknown message:%d/%d %s\n", cmn->h0, cmn->h1, hexdump(&hdr->data[0], l3_len));
	return -1;
}

static int mtp_link_regular_msg(struct mtp_link *link, struct mtp_level_3_hdr *hdr, int l3_len)
{
	struct msgb *out;
	struct mtp_level_3_mng *mng;

	if (hdr->ni != link->ni || l3_len < 1) {
		LOGP(DINP, LOGL_ERROR, "Unhandled data (ni: %d len: %d)\n",
		     hdr->ni, l3_len);
		return -1;
	}

	mng = (struct mtp_level_3_mng *) &hdr->data[0];
	LOGP(DINP, LOGL_DEBUG, "reg msg: h0: 0x%x h1: 0x%x\n",
             mng->cmn.h0, mng->cmn.h1);

	switch (mng->cmn.h0) {
	case MTP_TST_MSG_GRP:
		switch (mng->cmn.h1) {
		case MTP_TST_MSG_SLTM:
			/* simply respond to the request... */
			out = mtp_create_slta(link, mng, l3_len);
			if (!out)
				return -1;
			mtp_link_submit(link, out);
			return 0;
			break;
		case MTP_TST_MSG_SLTA:
			if (mng->length != 14) {
				LOGP(DINP, LOGL_ERROR, "Wrongly sized SLTA: %u\n", mng->length);
				return -1;
			}

			if (l3_len != 16) {
				LOGP(DINP, LOGL_ERROR, "Wrongly sized SLTA: %u\n", mng->length);
				return -1;
			}

			if (memcmp(mng->data, link->test_ptrn, sizeof(link->test_ptrn)) != 0) {
				LOGP(DINP, LOGL_ERROR, "Wrong test pattern SLTA\n");
				return -1;
			}

			/* we had a matching slta */
			bsc_del_timer(&link->t1_timer);
			link->sltm_pending = 0;
			return 0;
			break;
		}
		break;
	}

	return -1;
}

static int mtp_link_sccp_data(struct mtp_link *link, struct mtp_level_3_hdr *hdr, struct msgb *msg, int l3_len)
{
	struct msgb *out;
	struct sccp_con_ctrl_prt_mgt *prt;
	struct sccp_parse_result sccp;
	int type;

	msg->l2h = &hdr->data[0];
	if (msgb_l2len(msg) != l3_len) {
		LOGP(DINP, LOGL_ERROR, "Size is wrong after playing with the l2h header.\n");
		return -1;
	}

	if (!link->sccp_up) {
		LOGP(DINP, LOGL_ERROR, "SCCP traffic is not allowed.\n");
		return -1;
	}

	memset(&sccp, 0, sizeof(sccp));
	if (sccp_parse_header(msg, &sccp) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to parsed SCCP header.\n");
		return -1;
	}

	/* check if it is a SST */
	if (sccp_determine_msg_type(msg) == SCCP_MSG_TYPE_UDT
	    && msg->l3h[0] == SCCP_SST) {
		if (msgb_l3len(msg) != 5) {
			LOGP(DINP, LOGL_ERROR,
			     "SCCP UDT msg of unexpected size: %u\n",
			     msgb_l3len(msg));
			return -1;
		}

		prt = (struct sccp_con_ctrl_prt_mgt *) &msg->l3h[0];
		if (prt->apoc != MTP_MAKE_APOC(link->sccp_opc)) {
			LOGP(DINP, LOGL_ERROR, "Unknown APOC: %u/%u\n",
			     ntohs(prt->apoc), prt->apoc);
			type = SCCP_SSP;
		} else if (prt->assn != 1 && prt->assn != 254 &&
			   prt->assn != 7 && prt->assn != 8 && prt->assn != 146) {
			LOGP(DINP, LOGL_ERROR, "Unknown affected SSN assn: %u\n",
			     prt->assn);
			type = SCCP_SSP;
		} else {
			type = SCCP_SSA;
		}

		out = mtp_sccp_alloc_scmg(link, type, prt->assn,
					  MTP_LINK_SLS(hdr->addr));
		if (!out)
			return -1;

		mtp_link_submit(link, out);
		return 0;
	}

	mtp_link_forward_sccp(link, msg, MTP_LINK_SLS(hdr->addr));
	return 0;
}

int mtp_link_data(struct mtp_link *link, struct msgb *msg)
{
	int rc = -1;
	struct mtp_level_3_hdr *hdr;
	int l3_len;

	if (!msg->l2h || msgb_l2len(msg) < sizeof(*hdr))
		return -1;

	if (!link->running) {
		LOGP(DINP, LOGL_ERROR, "Link is not running. Call mtp_link_reset first: %p\n", link);
		return -1;
	}

	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	l3_len = msgb_l2len(msg) - sizeof(*hdr);

	switch (hdr->ser_ind) {
	case MTP_SI_MNT_SNM_MSG:
		rc = mtp_link_sign_msg(link, hdr, l3_len);
		break;
	case MTP_SI_MNT_REG_MSG:
		rc = mtp_link_regular_msg(link, hdr, l3_len);
		break;
	case MTP_SI_MNT_SCCP:
		rc = mtp_link_sccp_data(link, hdr, msg, l3_len);
		break;
	case MTP_SI_MNT_ISUP:
		msg->l3h = &hdr->data[0];
		rc = mtp_link_forward_isup(link, msg, MTP_LINK_SLS(hdr->addr));
		break;
	default:
		fprintf(stderr, "Unhandled: %u\n", hdr->ser_ind);
		break;
	}

	return rc;
}

int mtp_link_submit_sccp_data(struct mtp_link *link, int sls, const uint8_t *data, unsigned int length)
{

	if (!link->sccp_up) {
		LOGP(DINP, LOGL_ERROR, "SCCP msg after TRA and before SSA. Dropping it.\n");
		return -1;
	}

	return mtp_int_submit(link, link->sccp_opc, sls, MTP_SI_MNT_SCCP, data, length);
}

int mtp_link_submit_isup_data(struct mtp_link *link, int sls,
			      const uint8_t *data, unsigned int length)
{
	return mtp_int_submit(link, link->opc, sls, MTP_SI_MNT_ISUP, data, length);
}

static int mtp_int_submit(struct mtp_link *link, int pc, int sls, int type,
			  const uint8_t *data, unsigned int length)
{
	uint8_t *put_ptr;
	struct mtp_level_3_hdr *hdr;
	struct msgb *msg;

	msg = mtp_msg_alloc(link);
	if (!msg)
		return -1;

	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	hdr->ser_ind = type;

	hdr->addr = MTP_ADDR(sls % 16, link->dpc, pc);

	/* copy the raw sccp data */
	put_ptr = msgb_put(msg, length);
	memcpy(put_ptr, data, length);

	mtp_link_submit(link, msg);
	return 0;
}
