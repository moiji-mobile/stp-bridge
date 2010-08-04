/* Patch GSM 08.08 messages for the network and BS */
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

#include <bss_patch.h>
#include <cellmgr_debug.h>

#include <string.h>

#include <osmocore/gsm0808.h>
#include <osmocore/protocol/gsm_08_08.h>

#include <osmocom/sccp/sccp.h>

#include <arpa/inet.h>

static void patch_ass_rqst(struct msgb *msg, int length)
{
	struct tlv_parsed tp;
	uint8_t *data, audio;
	int len;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, length - 1, 0, 0);
	len = TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE);
	if (len < 3)
		return;

	data = (uint8_t *) TLVP_VAL(&tp, GSM0808_IE_CHANNEL_TYPE);
	/* no speech... ignore */
	if ((data[0] & 0xf) != 0x1)
		return;

	/* blindly assign */
	data[1] = GSM0808_SPEECH_FULL_PREF;
	audio = GSM0808_PERM_FR2;
	if (len > 3)
		audio |= 0x80;
	data[2] = audio;
}

static void patch_ass_cmpl(struct msgb *msg, int length)
{
	struct tlv_parsed tp;
	uint8_t *data;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, length - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CHOSEN_CHANNEL)) {
		LOGP(DMSC, LOGL_ERROR, "Chosen Channel not in the MSG.\n");
		return;
	}

	if (!TLVP_PRESENT(&tp, GSM0808_IE_SPEECH_VERSION)) {
		LOGP(DMSC, LOGL_ERROR, "Speech version not in the MSG.\n");
		return;
	}

	/* claim to have a TCH/H with no mode indication */
	data = (uint8_t *) TLVP_VAL(&tp, GSM0808_IE_CHOSEN_CHANNEL);
	data[0] = 0x09;

	data = (uint8_t *) TLVP_VAL(&tp, GSM0808_IE_SPEECH_VERSION);
	data[0] = GSM0808_PERM_HR3;
}

int bss_patch_filter_msg(struct msgb *msg, struct sccp_parse_result *sccp)
{
	int type;
	memset(sccp, 0, sizeof(*sccp));
	if (sccp_parse_header(msg, sccp) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Failed to parse SCCP header.\n");
		return -1;
	}

	type = sccp_determine_msg_type(msg);
	switch (type) {
	case SCCP_MSG_TYPE_CR:
		if (msg->l3h)
			break;
		return 0;
		break;
	case SCCP_MSG_TYPE_CC:
	case SCCP_MSG_TYPE_CREF:
		return 0;
		break;
	case SCCP_MSG_TYPE_RLC:
		return BSS_FILTER_RLC;
		break;
	case SCCP_MSG_TYPE_RLSD:
		return BSS_FILTER_RLSD;
		break;
	}

	if (msgb_l3len(msg) < sccp->data_len) {
		LOGP(DMSC, LOGL_ERROR, "Less space than there should be.\n");
		return -1;
	}

	if (!msg->l3h || msgb_l3len(msg) < 3) {
		return -1;
	}

	if (msg->l3h[0] != 0) {
		return -1;
	}

	if (msgb_l3len(msg) < 2 + msg->l3h[1]) {
		return -1;
	}

	switch (msg->l3h[2]) {
	case BSS_MAP_MSG_ASSIGMENT_RQST:
		msg->l3h = &msg->l3h[2];
		patch_ass_rqst(msg, sccp->data_len - 2);
		break;
	case BSS_MAP_MSG_ASSIGMENT_COMPLETE:
		msg->l3h = &msg->l3h[2];
		patch_ass_cmpl(msg, sccp->data_len - 2);
		break;
	case BSS_MAP_MSG_RESET:
		return BSS_FILTER_RESET;
		break;
	case BSS_MAP_MSG_RESET_ACKNOWLEDGE:
		return BSS_FILTER_RESET_ACK;
		break;
	case BSS_MAP_MSG_CLEAR_COMPLETE:
		return BSS_FILTER_CLEAR_COMPL;
		break;
	}

	return 0;
}

static void create_cr(struct msgb *target, struct msgb *inpt, struct sccp_parse_result *sccp)
{
	static const uint32_t optional_offset =
			offsetof(struct sccp_connection_request, optional_start);

	unsigned int optional_length, optional_start;
	struct sccp_connection_request *cr, *in_cr;

	target->l2h = msgb_put(target, sizeof(*cr));
	cr = (struct sccp_connection_request *) target->l2h;
	in_cr = (struct sccp_connection_request *) inpt->l2h;

	cr->type = in_cr->type;
	cr->proto_class = in_cr->proto_class;
	cr->source_local_reference = in_cr->source_local_reference;
	cr->variable_called = 2;
	cr->optional_start = 4;

	/* called address */
	target->l3h = msgb_put(target, 1 + 2);
	target->l3h[0] = 2;
	target->l3h[1] = 0x42;
	target->l3h[2] = 254;

	/*
	 * We need to keep the complete optional data. The SCCP parse result
         * is only pointing to the data payload.
	 */
	optional_start = in_cr->optional_start + optional_offset;
	optional_length = msgb_l2len(inpt) - optional_start;
	if (optional_start + optional_length <= msgb_l2len(inpt)) {
		target->l3h = msgb_put(target, optional_length);
		memcpy(target->l3h, inpt->l2h + optional_start, msgb_l3len(target));
	} else {
		LOGP(DINP, LOGL_ERROR, "Input should at least have a byte of data.\n");
	}
}

/*
 * Generate a simple UDT msg. FIXME: Merge it with the SCCP code
 */
static void create_udt(struct msgb *target, struct msgb *inpt, struct sccp_parse_result *sccp)
{
	struct sccp_data_unitdata *udt, *in_udt;

	target->l2h = msgb_put(target, sizeof(*udt));
	udt = (struct sccp_data_unitdata *) target->l2h;
	in_udt = (struct sccp_data_unitdata *) inpt->l2h;

	udt->type = in_udt->type;
	udt->proto_class = in_udt->proto_class;
	udt->variable_called = 3;
	udt->variable_calling = 5;
	udt->variable_data = 7;

	target->l3h = msgb_put(target, 1 + 2);
	target->l3h[0] = 2;
	target->l3h[1] = 0x42;
	target->l3h[2] = 254;

	target->l3h = msgb_put(target, 1 + 2);
	target->l3h[0] = 2;
	target->l3h[1] = 0x42;
	target->l3h[2] = 254;

	target->l3h = msgb_put(target, sccp->data_len + 1);
	target->l3h[0] = sccp->data_len;
	memcpy(&target->l3h[1], inpt->l3h, msgb_l3len(target) - 1);
}

void bss_rewrite_header_for_msc(int rc, struct msgb *target, struct msgb *inpt, struct sccp_parse_result *sccp)
{

	switch (inpt->l2h[0]) {
	case SCCP_MSG_TYPE_CR:
		if (rc >= 0)
			create_cr(target, inpt, sccp);
		else
			target->l2h = msgb_put(target, 0);
		break;
	case SCCP_MSG_TYPE_UDT:
		if (rc >= 0)
			create_udt(target, inpt, sccp);
		else
			target->l2h = msgb_put(target, 0);
		break;
	default:
		target->l2h = msgb_put(target, msgb_l2len(inpt));
		memcpy(target->l2h, inpt->l2h, msgb_l2len(target));
		break;
	}
}

/* it is asssumed that the SCCP stack checked the size */
static int patch_address(uint32_t offset, int pc, struct msgb *msg)
{
	struct sccp_called_party_address *party;
	uint8_t *the_pc;
	uint8_t pc_low, pc_high;

	party = (struct sccp_called_party_address *)(msg->l2h + offset + 1);
	the_pc = &party->data[0];

	pc_low = pc & 0xff;
	pc_high = (pc >> 8) & 0xff;
	the_pc[0] = pc_low;
	the_pc[1] = pc_high;

	return 0;
}
 
int bss_rewrite_header_to_bsc(struct msgb *msg, int opc, int dpc)
{
	static const uint32_t called_offset =
		offsetof(struct sccp_data_unitdata, variable_called);
	static const uint32_t calling_offset =
		offsetof(struct sccp_data_unitdata, variable_calling);

	struct sccp_data_unitdata *udt;
	struct sccp_parse_result sccp;

	memset(&sccp, 0, sizeof(sccp));
	if (sccp_parse_header(msg, &sccp) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Failed to parse SCCP header.\n");
		return -1;
	}

	/* For now the MSC only sends the PC in UDT */
	if (msg->l2h[0] != SCCP_MSG_TYPE_UDT)
		return 0;

	/* sanity checking */
	if (sccp.called.address.point_code_indicator != 1) {
		LOGP(DMSC, LOGL_ERROR, "MSC didn't send a PC in called address\n");
		return -1;
	}

	if (sccp.calling.address.point_code_indicator != 1) {
		LOGP(DMSC, LOGL_ERROR, "MSC didn't send a PC in calling address\n");
		return -1;
	}

	/* Good thing is we can avoid most of the error checking */
	udt = (struct sccp_data_unitdata *) msg->l2h;
	if (patch_address(called_offset + udt->variable_called, dpc, msg) != 0)
		return -1;

	if (patch_address(calling_offset + udt->variable_calling, opc, msg) != 0)
		return -1;
	return 0;
}
