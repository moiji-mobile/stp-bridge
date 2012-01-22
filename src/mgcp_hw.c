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

#include <cellmgr_debug.h>
#include <mgcp_ss7.h>

#ifndef NO_UNIPORTE
#include "NexusWare.h"

#define PTMC_STREAM_A_RX0	0
#define PTMC_STREAM_A_TX0	128
#define PTMC_STREAM_A_RX1	1024
#define PTMC_STREAM_A_TX1	1152


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
#endif

int mgcp_hw_init()
{
	return 0;
}

int mgcp_hw_loop(int trunk, int timeslot)
{
#ifdef NO_UNIPORTE
	return 0;
#else
	return PTI_ConnectHSCM(PTI_HSCM_TRUNK + trunk, timeslot - 1,
			       PTI_HSCM_TRUNK + trunk, timeslot - 1, 1, 1);
#endif
}

int mgcp_hw_connect(int port, int trunk, int timeslot)
{
#ifdef NO_UNIPORTE
#warning "NO Uniporte"
#else
	int status;
	int _rx_port, _tx_port;

	/* rx port, tx side for the port */
	_rx_port = rx_port_get(port);
	_tx_port = tx_port_get(port);

	status = PTI_ConnectHSCM(PTI_HSCM_TRUNK + trunk, timeslot - 1,
				 PTI_HSCM_PTMC, _rx_port, 1, 0);
	if (status != 0)
		return -1;

	status = PTI_ConnectHSCM(PTI_HSCM_PTMC, _tx_port,
				 PTI_HSCM_TRUNK + trunk, timeslot - 1, 1, 0);
	if (status != 0)
		return -1;
#endif
	return 0;
}
