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
#ifndef snmp_mtp_h
#define snmp_mtp_h

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/utilities.h>
#include <net-snmp/net-snmp-includes.h>

struct snmp_mtp_session {
	netsnmp_session session, *ss;
};

void snmp_mtp_start_c7_datalink(struct snmp_mtp_session *, int link_id);
void snmp_mtp_stop_c7_datalink(struct snmp_mtp_session *, int link_id);

struct snmp_mtp_session *snmp_mtp_session_create(char *host);
void snmp_mtp_deactivate(struct snmp_mtp_session *, int link_id);
void snmp_mtp_activate(struct snmp_mtp_session *, int link_id);

#endif
