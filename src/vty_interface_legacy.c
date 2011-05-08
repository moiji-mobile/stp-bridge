/* VTY code for the Cellmgr */
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

#include <bsc_data.h>
#include <mtp_pcap.h>
#include <msc_connection.h>
#include <ss7_application.h>
#include <ss7_vty.h>
#include <cellmgr_debug.h>

#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/vty.h>

#include <unistd.h>
#include <netdb.h>

#undef PACKAGE_NAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#undef PACKAGE_TARNAME
#undef PACKAGE_STRING
#include <cellmgr_config.h>

extern struct bsc_data *bsc;

static struct vty_app_info vty_info = {
	.name 		= "Cellmgr-ng",
	.version	= VERSION,
	.go_parent_cb	= NULL,
};

/* vty code */
static struct cmd_node cell_node = {
	CELLMGR_NODE,
	"%s(cellmgr)#",
	1,
};

static int config_write_cell(struct vty *vty)
{
	struct mtp_link_set *set = mtp_link_set_num(bsc, 0);
	struct msc_connection *msc = msc_connection_num(bsc, 0);
	struct ss7_application *app = ss7_application_num(bsc, 0);

	vty_out(vty, "cellmgr%s", VTY_NEWLINE);
	vty_out(vty, " mtp dpc %d%s", set->dpc, VTY_NEWLINE);
	vty_out(vty, " mtp opc %d%s", set->opc, VTY_NEWLINE);
	vty_out(vty, " mtp sccp-opc %d%s", set->sccp_opc, VTY_NEWLINE);
	vty_out(vty, " mtp ni %d%s", set->ni, VTY_NEWLINE);
	vty_out(vty, " mtp spare %d%s", set->spare, VTY_NEWLINE);
	vty_out(vty, " mtp sltm once %d%s", set->sltm_once, VTY_NEWLINE);
	if (bsc->udp_ip)
		vty_out(vty, " udp dest ip %s%s", bsc->udp_ip, VTY_NEWLINE);
	vty_out(vty, " udp dest port %d%s", bsc->udp_port, VTY_NEWLINE);
	vty_out(vty, " udp src port %d%s", bsc->udp_src_port, VTY_NEWLINE);
	vty_out(vty, " udp reset %d%s", bsc->udp_reset_timeout, VTY_NEWLINE);
	vty_out(vty, " udp number-links %d%s", bsc->udp_nr_links, VTY_NEWLINE);
	vty_out(vty, " isup pass-through %d%s", app->isup_pass, VTY_NEWLINE);

	if (msc) {
		vty_out(vty, " msc ip %s%s", msc->ip, VTY_NEWLINE);
		vty_out(vty, " msc ip-dscp %d%s", msc->dscp, VTY_NEWLINE);
		vty_out(vty, " msc token %s%s", msc->token, VTY_NEWLINE);
	}


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
	struct mtp_link_set *set = mtp_link_set_num(bsc, 0);
	set->dpc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_opc, cfg_net_opc_cmd,
      "mtp opc OPC_NR",
      "Set the OPC to be used.")
{
	struct mtp_link_set *set = mtp_link_set_num(bsc, 0);
	set->opc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_sccp_opc, cfg_net_sccp_opc_cmd,
      "mtp sccp-opc OPC_NR",
      "Set the SCCP OPC to be used.")
{
	struct mtp_link_set *set = mtp_link_set_num(bsc, 0);
	set->sccp_opc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_mtp_ni, cfg_net_mtp_ni_cmd,
      "mtp ni NR",
      "Set the MTP NI to be used.\n" "NR")
{
	struct mtp_link_set *set = mtp_link_set_num(bsc, 0);
	set->ni = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_mtp_spare, cfg_net_mtp_spare_cmd,
      "mtp spare NR",
      "Set the MTP Spare to be used.\n" "NR")
{
	struct mtp_link_set *set = mtp_link_set_num(bsc, 0);
	set->spare = atoi(argv[0]);
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
	bsc->udp_ip = talloc_strdup(NULL, inet_ntoa(*addr));
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_dst_port, cfg_udp_dst_port_cmd,
      "udp dest port PORT_NR",
      "If UDP mode is used specify the UDP dest port")
{
	bsc->udp_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_src_port, cfg_udp_src_port_cmd,
      "udp src port PORT_NR",
      "Set the UDP source port to be used.")
{
	bsc->udp_src_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_reset, cfg_udp_reset_cmd,
      "udp reset TIMEOUT",
      "Set the timeout to take the link down")
{
	bsc->udp_reset_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_nr_links, cfg_udp_nr_links_cmd,
      "udp number-links <1-32>",
      "Set the number of links to use\n")
{
	bsc->udp_nr_links = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_sltm_once, cfg_sltm_once_cmd,
      "mtp sltm once (0|1)",
      "Send SLTMs until the link is established.")
{
	struct mtp_link_set *set = mtp_link_set_num(bsc, 0);
	set->sltm_once = !!atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_ip, cfg_msc_ip_cmd,
      "msc ip IP",
      "Set the MSC IP")
{
	struct hostent *hosts;
	struct in_addr *addr;
	struct msc_connection *msc = msc_connection_num(bsc, 0);

	if (!msc) {
		vty_out(vty, "%%No MSC Connection defined in this app.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	hosts = gethostbyname(argv[0]);
	if (!hosts || hosts->h_length < 1 || hosts->h_addrtype != AF_INET) {
		vty_out(vty, "Failed to resolve '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	addr = (struct in_addr *) hosts->h_addr_list[0];

	if (msc->ip)
		talloc_free(msc->ip);
	msc->ip = talloc_strdup(msc, inet_ntoa(*addr));
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_ip_dscp, cfg_msc_ip_dscp_cmd,
      "msc ip-dscp <0-255>",
      "Set the IP DSCP on the A-link\n"
      "Set the DSCP in IP packets to the MSC")
{
	struct msc_connection *msc = msc_connection_num(bsc, 0);

	if (!msc) {
		vty_out(vty, "%%No MSC Connection defined in this app.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	msc->dscp = atoi(argv[0]);
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
	struct msc_connection *msc = msc_connection_num(bsc, 0);

	if (!msc) {
		vty_out(vty, "%%No MSC Connection defined in this app.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (msc->token)
		talloc_free(msc->token);
	msc->token = talloc_strdup(msc, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_ping_time, cfg_ping_time_cmd,
      "timeout ping NR",
      "Set the PING interval. Negative to disable it")
{
	struct msc_connection *msc = msc_connection_num(bsc, 0);

	if (!msc) {
		vty_out(vty, "%%No MSC Connection defined in this app.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	msc->ping_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_pong_time, cfg_pong_time_cmd,
      "timeout pong NR",
      "Set the PING interval. Negative to disable it")
{
	struct msc_connection *msc = msc_connection_num(bsc, 0);

	if (!msc) {
		vty_out(vty, "%%No MSC Connection defined in this app.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	msc->pong_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_time, cfg_msc_time_cmd,
      "timeout msc NR",
      "Set the MSC connect timeout")
{
	struct msc_connection *msc = msc_connection_num(bsc, 0);

	if (!msc) {
		vty_out(vty, "%%No MSC Connection defined in this app.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	msc->msc_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_isup_pass, cfg_isup_pass_cmd,
      "isup pass-through (0|1)",
      "ISUP related functionality\n"
      "Pass through all ISUP messages directly\n"
      "Handle some messages locally\n" "Pass through everything\n")
{
	struct ss7_application *app = ss7_application_num(bsc, 0);
	ss7_application_pass_isup(app, atoi(argv[0]));

	return CMD_SUCCESS;
}

extern void cell_vty_init_cmds(void);
void cell_vty_init(void)
{
	cmd_init(1);
	vty_init(&vty_info);
	logging_vty_add_cmds(&log_info);

	install_element(CONFIG_NODE, &cfg_cell_cmd);
	install_node(&cell_node, config_write_cell);

	install_element(CELLMGR_NODE, &cfg_net_dpc_cmd);
	install_element(CELLMGR_NODE, &cfg_net_opc_cmd);
	install_element(CELLMGR_NODE, &cfg_net_sccp_opc_cmd);
	install_element(CELLMGR_NODE, &cfg_net_mtp_ni_cmd);
	install_element(CELLMGR_NODE, &cfg_net_mtp_spare_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_dst_ip_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_dst_port_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_src_port_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_reset_cmd);
	install_element(CELLMGR_NODE, &cfg_udp_nr_links_cmd);
	install_element(CELLMGR_NODE, &cfg_sltm_once_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_ip_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_token_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_ip_dscp_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_ip_tos_cmd);
	install_element(CELLMGR_NODE, &cfg_ping_time_cmd);
	install_element(CELLMGR_NODE, &cfg_pong_time_cmd);
	install_element(CELLMGR_NODE, &cfg_msc_time_cmd);
	install_element(CELLMGR_NODE, &cfg_isup_pass_cmd);

	cell_vty_init_cmds();
}

const char *openbsc_copyright = "";
