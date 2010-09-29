/* VTY code for the Cellmgr */
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

#include <bsc_data.h>

#include <osmocore/talloc.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>

#include <unistd.h>
#include <netdb.h>

#undef PACKAGE_NAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#undef PACKAGE_TARNAME
#undef PACKAGE_STRING
#include <cellmgr_config.h>

extern struct bsc_data bsc;

static struct vty_app_info vty_info = {
	.name 		= "Cellmgr-ng",
	.version	= VERSION,
	.go_parent_cb	= NULL,
};

/* vty code */
enum cellmgr_node {
	CELLMGR_NODE = _LAST_OSMOVTY_NODE,
};

static struct cmd_node cell_node = {
	CELLMGR_NODE,
	"%s(cellmgr)#",
	1,
};

static int config_write_cell(struct vty *vty)
{
	vty_out(vty, "cellmgr%s", VTY_NEWLINE);
	vty_out(vty, " mtp dpc %d%s", bsc.dpc, VTY_NEWLINE);
	vty_out(vty, " mtp opc %d%s", bsc.opc, VTY_NEWLINE);
	if (bsc.udp_ip)
		vty_out(vty, " udp dest ip %s%s", bsc.udp_ip, VTY_NEWLINE);
	vty_out(vty, " udp dest port %d%s", bsc.udp_port, VTY_NEWLINE);
	vty_out(vty, " udp src port %d%s", bsc.src_port, VTY_NEWLINE);
	vty_out(vty, " udp reset %d%s", bsc.link.udp.reset_timeout, VTY_NEWLINE);
	vty_out(vty, " mtp sltm once %d%s", bsc.once, VTY_NEWLINE);
	vty_out(vty, " msc ip %s%s", bsc.msc_address, VTY_NEWLINE);
	vty_out(vty, " msc ip-dscp %d%s", bsc.msc_ip_dscp, VTY_NEWLINE);
	vty_out(vty, " msc token %s%s", bsc.token, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_cell, cfg_cell_cmd,
      "cellmgr", "Configure the Cellmgr")
{
	vty->node = CELLMGR_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_dpc, cfg_net_dpc_cmd,
      "mtp dpc DPC_NR",
      "Set the DPC to be used.")
{
	bsc.dpc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_opc, cfg_net_opc_cmd,
      "mtp opc OPC_NR",
      "Set the OPC to be used.")
{
	bsc.opc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_dst_ip, cfg_udp_dst_ip_cmd,
      "udp dest ip IP",
      "Set the IP when UDP mode is supposed to be used.")
{
	struct hostent *hosts;
	struct in_addr *addr;

	hosts = gethostbyname(argv[0]);
	if (!hosts || hosts->h_length < 1 || hosts->h_addrtype != AF_INET) {
		vty_out(vty, "Failed to resolve '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	addr = (struct in_addr *) hosts->h_addr_list[0];
	bsc.udp_ip = talloc_strdup(NULL, inet_ntoa(*addr));
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_dst_port, cfg_udp_dst_port_cmd,
      "udp dest port PORT_NR",
      "If UDP mode is used specify the UDP dest port")
{
	bsc.udp_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_src_port, cfg_udp_src_port_cmd,
      "udp src port PORT_NR",
      "Set the UDP source port to be used.")
{
	bsc.src_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_reset, cfg_udp_reset_cmd,
      "udp reset TIMEOUT",
      "Set the timeout to take the link down")
{
	bsc.link.udp.reset_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_sltm_once, cfg_sltm_once_cmd,
      "mtp sltm once (0|1)",
      "Send SLTMs until the link is established.")
{
	bsc.once = !!atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_ip, cfg_msc_ip_cmd,
      "msc ip IP",
      "Set the MSC IP")
{
	struct hostent *hosts;
	struct in_addr *addr;

	hosts = gethostbyname(argv[0]);
	if (!hosts || hosts->h_length < 1 || hosts->h_addrtype != AF_INET) {
		vty_out(vty, "Failed to resolve '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	addr = (struct in_addr *) hosts->h_addr_list[0];

	bsc.msc_address = talloc_strdup(NULL, inet_ntoa(*addr));
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_ip_dscp, cfg_msc_ip_dscp_cmd,
      "msc ip-dscp <0-255>",
      "Set the IP DSCP on the A-link\n"
      "Set the DSCP in IP packets to the MSC")
{
	bsc.msc_ip_dscp = atoi(argv[0]);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_msc_ip_dscp, cfg_msc_ip_tos_cmd,
      "msc ip-tos <0-255>",
      "Set the IP DSCP on the A-link\n"
      "Set the DSCP in IP packets to the MSC")

DEFUN(cfg_msc_token, cfg_msc_token_cmd,
      "msc token TOKEN",
      "Set the Token to be used for the MSC")
{
	bsc.token = talloc_strdup(NULL, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_ping_time, cfg_ping_time_cmd,
      "timeout ping NR",
      "Set the PING interval. Negative to disable it")
{
	bsc.ping_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_pong_time, cfg_pong_time_cmd,
      "timeout pong NR",
      "Set the PING interval. Negative to disable it")
{
	bsc.pong_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_time, cfg_msc_time_cmd,
      "timeout msc NR",
      "Set the MSC connect timeout")
{
	bsc.msc_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

void cell_vty_init(void)
{
	cmd_init(1);
	vty_init(&vty_info);

	install_element(CONFIG_NODE, &cfg_cell_cmd);
	install_node(&cell_node, config_write_cell);

	install_element(CELLMGR_NODE, &cfg_net_dpc_cmd);
	install_element(CELLMGR_NODE, &cfg_net_opc_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_dst_ip_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_dst_port_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_src_port_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_reset_cmd);
	install_element(CELLMGR_NODE, &cfg_sltm_once_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_ip_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_token_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_ip_dscp_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_ip_tos_cmd);
	install_element(CELLMGR_NODE, &cfg_ping_time_cmd);
	install_element(CELLMGR_NODE, &cfg_pong_time_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_time_cmd);
}

const char *openbsc_copyright = "";
