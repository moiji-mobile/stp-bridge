/* GSM 08.08 BSSMAP handling						*/
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by on-waves.com
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

#include <openbsc_nat/bssap.h>
#include <openbsc_nat/tlv.h>

#include <osmocom/sccp/sccp.h>

#include <arpa/inet.h>
#include <assert.h>


#define BSSMAP_MSG_SIZE 512
#define BSSMAP_MSG_HEADROOM 128


static const struct tlv_definition bss_att_tlvdef = {
	.def = {
		[GSM0808_IE_IMSI]		    = { TLV_TYPE_TLV },
		[GSM0808_IE_TMSI]		    = { TLV_TYPE_TLV },
		[GSM0808_IE_CELL_IDENTIFIER_LIST]   = { TLV_TYPE_TLV },
		[GSM0808_IE_CHANNEL_NEEDED]	    = { TLV_TYPE_TV },
		[GSM0808_IE_EMLPP_PRIORITY]	    = { TLV_TYPE_TV },
		[GSM0808_IE_CHANNEL_TYPE]	    = { TLV_TYPE_TLV },
		[GSM0808_IE_PRIORITY]		    = { TLV_TYPE_TLV },
		[GSM0808_IE_CIRCUIT_IDENTITY_CODE]  = { TLV_TYPE_TV },
		[GSM0808_IE_DOWNLINK_DTX_FLAG]	    = { TLV_TYPE_TV },
		[GSM0808_IE_INTERFERENCE_BAND_TO_USE] = { TLV_TYPE_TV },
		[GSM0808_IE_CLASSMARK_INFORMATION_T2] = { TLV_TYPE_TLV },
		[GSM0808_IE_GROUP_CALL_REFERENCE]   = { TLV_TYPE_TLV },
		[GSM0808_IE_TALKER_FLAG]	    = { TLV_TYPE_T },
		[GSM0808_IE_CONFIG_EVO_INDI]	    = { TLV_TYPE_TV },
		[GSM0808_IE_LSA_ACCESS_CTRL_SUPPR]  = { TLV_TYPE_TV },
		[GSM0808_IE_SERVICE_HANDOVER]	    = { TLV_TYPE_TV},
		[GSM0808_IE_ENCRYPTION_INFORMATION] = { TLV_TYPE_TLV },
		[GSM0808_IE_CIPHER_RESPONSE_MODE]   = { TLV_TYPE_TV },
		[GSM0808_IE_SPEECH_VERSION]	    = { TLV_TYPE_TV },
		[GSM0808_IE_CHOSEN_ENCR_ALG]	    = { TLV_TYPE_TV },
		[GSM0808_IE_CHOSEN_CHANNEL]	    = { TLV_TYPE_TV },
	},
};

const struct tlv_definition *gsm0808_att_tlvdef()
{
	return &bss_att_tlvdef;
}

