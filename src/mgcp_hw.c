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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/utilities.h>
#include <net-snmp/net-snmp-includes.h>

#include <cellmgr_debug.h>

#define HSCOMM "PTI-NexusWare-HSCMCONN-MIB::"

#define PTMC_STREAM_A_RX0	0
#define PTMC_STREAM_A_TX0	128
#define PTMC_STREAM_A_RX1	1024
#define PTMC_STREAM_A_TX1	1152


static netsnmp_session g_session, *g_ss;

static void add_pdu_var(netsnmp_pdu *pdu, const char *mib_name,
			int id1, int id2, const char *value)
{
	oid oid_name[MAX_OID_LEN];
	size_t name_length;

	char buf[4096];
	buf[4095] = '\0';
	snprintf(buf, sizeof(buf)-1, "%s.%d.%d", mib_name, id1, id2);

	name_length = MAX_OID_LEN;
	if (snmp_parse_oid(buf, oid_name, &name_length) == NULL) {
		snmp_perror(buf);
		return;
	}

	if (snmp_add_var(pdu, oid_name, name_length, 'i', value)) {
		snmp_perror(buf);
		return;
	}
}

static int rx_port_get(int port)
{
	if (port > 60)
		return PTMC_STREAM_A_RX1 + port;
	else
		return PTMC_STREAM_A_RX0 + port;
}

static int tx_port_get(int port)
{
	if (port > 60)
		return PTMC_STREAM_A_TX1 + port;
	else
		return PTMC_STREAM_A_TX0 + port;
}

int mgcp_snmp_init()
{
	init_snmp("mgcp_mgw");
	snmp_sess_init(&g_session);
	g_session.version = SNMP_VERSION_1;
	g_session.community = (unsigned char *) "private";
	g_session.community_len = strlen((const char *) g_session.community);

	g_session.peername = "127.0.0.1";
	g_ss = snmp_open(&g_session);
	if (!g_ss) {
		snmp_perror("create failure");
		snmp_log(LOG_ERR, "Could not connect to the remote.\n");
		LOGP(DINP, LOGL_ERROR, "Failed to open a SNMP session.\n");
		return -1;
	}

	return 0;
}

int mgcp_snmp_connect(int port, int trunk, int timeslot)
{
	int status;
	netsnmp_pdu *response = NULL;
	netsnmp_pdu *pdu;
	int _rx_port, _tx_port;
	char tx_port[10];
	char trunk_name[13], tslot_name[13];

	if (!g_ss)
		return -1;

	/* have the trunk/timeslot as value */
	snprintf(trunk_name, sizeof(trunk_name), "%d", trunk);
	snprintf(tslot_name, sizeof(tslot_name), "%d", timeslot);

	/* rx port, tx side for the port */
	_rx_port = rx_port_get(port);
	_tx_port = tx_port_get(port);
	snprintf(tx_port, sizeof(tx_port), "%d", _tx_port);

	pdu = snmp_pdu_create(SNMP_MSG_SET);
	if (!pdu) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate PDU.\n");
		return -1;
	}

	/* This connects the TX side to the given trunk/timeslot */
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourceType.hscmconnStreamTrunk",
		    trunk, timeslot, "hscmconnStreamPtmc");
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourceTypeInstance.hscmconnStreamTrunk",
		    trunk, timeslot, "1");
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourceTimeslot.hscmconnStreamTrunk",
		    trunk, timeslot, tx_port);
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourcePattern.hscmconnStreamTrunk",
		    trunk, timeslot, "0");
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourceTimeslotCount.hscmconnStreamTrunk",
		    trunk, timeslot, "1");
	add_pdu_var(pdu, HSCOMM "hscmconnConnectBidirectional.hscmconnStreamTrunk",
		    trunk, timeslot, "false");

	/* This connect the RX side to the given trunk/timeslot */
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourceType.hscmconnStreamPtmc",
		    1, _rx_port, "hscmconnStreamTrunk");
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourceTypeInstance.hscmconnStreamPtmc",
		    1, _rx_port, trunk_name);
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourceTimeslot.hscmconnStreamPtmc",
		    1, _rx_port, tslot_name);
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourcePattern.hscmconnStreamPtmc",
		    1, _rx_port, "0");
	add_pdu_var(pdu, HSCOMM "hscmconnNewDataSourceTimeslotCount.hscmconnStreamPtmc",
		    1, _rx_port, "1");
	add_pdu_var(pdu, HSCOMM "hscmconnConnectBidirectional.hscmconnStreamPtmc",
		    1, _rx_port, "false");


	status = snmp_synch_response(g_ss, pdu, &response);
	if (status == STAT_ERROR) {
		snmp_sess_perror("set failed", g_ss);
		goto failure;
	} else if (status == STAT_TIMEOUT) {
		fprintf(stderr, "Timeout for SNMP.\n");
		goto failure;
	}

	if (response)
		snmp_free_pdu(response);
	return 0;

failure:
	if (response)
		snmp_free_pdu(response);
	return -1;
}
