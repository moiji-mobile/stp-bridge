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

#include <osmocore/talloc.h>
#include <osmocore/gsm48.h>
#include <osmocore/rate_ctr.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/vty.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
	vty_out(vty, " mtp sccp-opc %d%s", bsc.sccp_opc, VTY_NEWLINE);
	vty_out(vty, " mtp ni %d%s", bsc.ni_ni, VTY_NEWLINE);
	vty_out(vty, " mtp spare %d%s", bsc.ni_spare, VTY_NEWLINE);
	vty_out(vty, " mtp sltm once %d%s", bsc.once, VTY_NEWLINE);
	vty_out(vty, " country-code %d%s", bsc.mcc, VTY_NEWLINE);
	vty_out(vty, " network-code %d%s", bsc.mnc, VTY_NEWLINE);
	vty_out(vty, " location-area-code %d%s", bsc.lac, VTY_NEWLINE);
	if (bsc.udp_ip)
		vty_out(vty, " udp dest ip %s%s", bsc.udp_ip, VTY_NEWLINE);
	vty_out(vty, " udp dest port %d%s", bsc.udp_port, VTY_NEWLINE);
	vty_out(vty, " udp src port %d%s", bsc.src_port, VTY_NEWLINE);
	vty_out(vty, " udp reset %d%s", bsc.udp_reset_timeout, VTY_NEWLINE);
	vty_out(vty, " udp number-links %d%s", bsc.udp_nr_links, VTY_NEWLINE);
	vty_out(vty, " msc ip %s%s", bsc.msc_address, VTY_NEWLINE);
	vty_out(vty, " msc ip-dscp %d%s", bsc.msc_ip_dscp, VTY_NEWLINE);
	vty_out(vty, " msc token %s%s", bsc.token, VTY_NEWLINE);
	vty_out(vty, " isup pass-through %d%s", bsc.isup_pass, VTY_NEWLINE);

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

DEFUN(cfg_net_sccp_opc, cfg_net_sccp_opc_cmd,
      "mtp sccp-opc OPC_NR",
      "Set the SCCP OPC to be used.")
{
	bsc.sccp_opc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_mtp_ni, cfg_net_mtp_ni_cmd,
      "mtp ni NR",
      "Set the MTP NI to be used.\n" "NR")
{
	bsc.ni_ni = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_mtp_spare, cfg_net_mtp_spare_cmd,
      "mtp spare NR",
      "Set the MTP Spare to be used.\n" "NR")
{
	bsc.ni_spare = atoi(argv[0]);
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
	bsc.udp_reset_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_udp_nr_links, cfg_udp_nr_links_cmd,
      "udp number-links <1-32>",
      "Set the number of links to use\n")
{
	bsc.udp_nr_links = atoi(argv[0]);
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

static void update_lai(struct bsc_data *bsc)
{
	gsm48_generate_lai(&bsc->lai, bsc->mcc, bsc->mnc, bsc->lac);
}

DEFUN(cfg_mnc, cfg_mnc_cmd,
      "network-code NR",
      "Set the Mobile Network Code\n" "Number\n")
{
	bsc.mnc = atoi(argv[0]);
	update_lai(&bsc);
	return CMD_SUCCESS;
}

DEFUN(cfg_mcc, cfg_mcc_cmd,
      "country-code NR",
      "Set the Mobile Country Code\n" "Number\n")
{
	bsc.mcc = atoi(argv[0]);
	update_lai(&bsc);
	return CMD_SUCCESS;
}

DEFUN(cfg_lac, cfg_lac_cmd,
      "location-area-code NR",
      "Set the Location Area Code\n" "Number\n")
{
	bsc.lac = atoi(argv[0]);
	update_lai(&bsc);
	return CMD_SUCCESS;
}

DEFUN(cfg_isup_pass, cfg_isup_pass_cmd,
      "isup pass-through (0|1)",
      "ISUP related functionality\n"
      "Pass through all ISUP messages directly\n"
      "Handle some messages locally\n" "Pass through everything\n")
{
	bsc.isup_pass = atoi(argv[0]);
	if (bsc.m2ua_set)
		bsc.m2ua_set->pass_all_isup = bsc.isup_pass;
	if (bsc.link_set)
		bsc.link_set->pass_all_isup = bsc.isup_pass;

	return CMD_SUCCESS;
}

static void dump_stats(struct vty *vty, const char *name, struct mtp_link_set *set)
{
	struct mtp_link *link;

	vty_out(vty, "Linkset name: %s opc: %d%s", name, set->opc, VTY_NEWLINE);
	vty_out_rate_ctr_group(vty, " ", set->ctrg);

	llist_for_each_entry(link, &set->links, entry) {
		vty_out(vty, " Link %d%s", link->link_no, VTY_NEWLINE);
		vty_out_rate_ctr_group(vty, "  ", link->ctrg);
	}
}

DEFUN(show_stats, show_stats_cmd,
      "show statistics",
      SHOW_STR "Display Linkset statistics\n")
{
	if (bsc.link_set)
		dump_stats(vty, "MTP ", bsc.link_set);
	if (bsc.m2ua_set && bsc.app == APP_STP)
		dump_stats(vty, "M2UA", bsc.m2ua_set);
	return CMD_SUCCESS;
}

static void dump_state(struct vty *vty, const char *name, struct mtp_link_set *set)
{
	struct mtp_link *link;

	if (!set) {
		vty_out(vty, "LinkSet for %s is not configured.%s", name, VTY_NEWLINE);
		return;
	}

	vty_out(vty, "LinkSet for %s is %s, remote sccp is %s.%s",
		name,
		set->available == 0 ? "not available" : "available",
		set->sccp_up == 0? "not established" : "established",
		VTY_NEWLINE);

	llist_for_each_entry(link, &set->links, entry) {
		if (link->blocked)
			vty_out(vty, " Link %d is blocked.%s",
				link->link_no, VTY_NEWLINE);
		else
			vty_out(vty, " Link %d is %s.%s",
				link->link_no,
				link->available == 0 ? "not available" : "available",
				VTY_NEWLINE);
	}
}

DEFUN(show_linksets, show_linksets_cmd,
      "show link-sets",
      SHOW_STR "Display current state of linksets\n")
{
	dump_state(vty, "MTP ", bsc.link_set);
	if (bsc.app == APP_STP)
		dump_state(vty, "M2UA", bsc.m2ua_set);
	return CMD_SUCCESS;
}

DEFUN(show_msc, show_msc_cmd,
      "show msc",
      SHOW_STR "Display the status of the MSC\n")
{
	vty_out(vty, "MSC link is %s and had %s.%s",
		bsc.msc_link_down == 0 ? "up" : "down",
		bsc.first_contact == 1 ? "no contact" : "contact",
		VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_slc, show_slc_cmd,
      "show link-set (mtp|m2ua) slc",
      SHOW_STR "LinkSet\n" "MTP Linkset\n" "M2UA LinkSet\n" "SLS to SLC\n")
{
	struct mtp_link_set *set = NULL;
	int i;

	if (bsc.link_set && strcmp(argv[0], "mtp") == 0)
		set = bsc.link_set;
	else if (bsc.m2ua_set && strcmp(argv[0], "m2ua") == 0)
		set = bsc.m2ua_set;

	if (!set) {
		vty_out(vty, "Failed to find linkset.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "LinkSet for %s.%s", argv[0], VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(set->slc); ++i) {
		if (set->slc[i])
			vty_out(vty, " SLC[%.2d] is on link %d.%s",
				i, set->slc[i]->link_no, VTY_NEWLINE);
		else
			vty_out(vty, " SLC[%d] is down.%s",
				i, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(pcap_set, pcap_set_cmd,
      "trace-pcap set (m2ua|mtp) FILE",
      "Trace to a PCAP file\n" "Trace a linkset\n"
      "Trace m2ua linkset\n" "Trace mtp linkset\n" "Filename to trace\n")
{
	struct mtp_link_set *set = NULL;

	if (bsc.link_set && strcmp(argv[0], "mtp") == 0)
		set = bsc.link_set;
	else if (bsc.m2ua_set && strcmp(argv[0], "m2ua") == 0)
		set = bsc.m2ua_set;

	if (!set) {
		vty_out(vty, "Failed to find linkset.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}


	if (set->pcap_fd >= 0 && bsc.pcap_fd != set->pcap_fd)
		close(set->pcap_fd);
	set->pcap_fd = open(argv[1], O_WRONLY | O_TRUNC | O_CREAT,
			    S_IRUSR | S_IWUSR | S_IRGRP| S_IROTH);
	if (set->pcap_fd < 0) {
		vty_out(vty, "Failed to open file for writing.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	mtp_pcap_write_header(set->pcap_fd);
	return CMD_SUCCESS;
}

DEFUN(pcap_set_stop, pcap_set_stop_cmd,
      "trace-pcap set (m2ua|mtp) stop",
      "Trace to a PCAP file\n" "Trace a linkset\n"
      "Trace m2ua linkset\n" "Trace mtp linkset\n" "Stop the tracing\n")
{
	struct mtp_link_set *set = NULL;

	if (bsc.link_set && strcmp(argv[0], "mtp") == 0)
		set = bsc.link_set;
	else if (bsc.m2ua_set && strcmp(argv[0], "m2ua") == 0)
		set = bsc.m2ua_set;

	if (!set) {
		vty_out(vty, "Failed to find linkset.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (set->pcap_fd >= 0 && bsc.pcap_fd != set->pcap_fd)
		close(set->pcap_fd);
	set->pcap_fd = -1;
	return CMD_SUCCESS;
}

#define FIND_LINK(vty, type, nr) ({						\
	struct mtp_link_set *set = NULL;					\
	struct mtp_link *link = NULL, *tmp;					\
	if (strcmp(type, "mtp") == 0)						\
		set = bsc.link_set;						\
	else if (strcmp(type, "m2ua") == 0)					\
		set = bsc.m2ua_set;						\
	else {									\
		vty_out(vty, "Unknown linkset %s.%s", type, VTY_NEWLINE);	\
		return CMD_WARNING;						\
	}									\
	llist_for_each_entry(tmp, &set->links, entry) {				\
		if (tmp->link_no == nr) {					\
			link = tmp;						\
			break;							\
		}								\
	}									\
	if (!link) {								\
		vty_out(vty, "Can not find link %d.%s", nr, VTY_NEWLINE);	\
		return CMD_WARNING;						\
	}									\
	link; })

#define LINK_STR "Operations on the link\n"					\
		 "MTP Linkset\n" "M2UA Linkset\n"				\
		 "Link number\n"

DEFUN(lnk_block, lnk_block_cmd,
      "link (mtp|m2ua) <0-15> block",
      LINK_STR "Block it\n")
{
	struct mtp_link *link = FIND_LINK(vty, argv[0], atoi(argv[1]));
	mtp_link_block(link);
	return CMD_SUCCESS;
}

DEFUN(lnk_unblock, lnk_unblock_cmd,
      "link (mtp|m2ua) <0-15> unblock",
      LINK_STR "Unblock it\n")
{
	struct mtp_link *link = FIND_LINK(vty, argv[0], atoi(argv[1]));
	mtp_link_unblock(link);
	return CMD_SUCCESS;
}

DEFUN(lnk_reset, lnk_reset_cmd,
      "link (mtp|m2ua) <0-15> reset",
      LINK_STR "Reset it\n")
{
	struct mtp_link *link = FIND_LINK(vty, argv[0], atoi(argv[1]));
	mtp_link_failure(link);
	return CMD_SUCCESS;
}

DEFUN(allow_inject, allow_inject_cmd,
      "allow-inject (0|1)",
      "Allow to inject messages\n" "Disable\n" "Enable\n")
{
	bsc.allow_inject = atoi(argv[0]);
	return CMD_SUCCESS;
}

void cell_vty_init(void)
{
	cmd_init(1);
	vty_init(&vty_info);
	logging_vty_add_cmds();

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
	install_element(CELLMGR_NODE, &cfg_mcc_cmd);
	install_element(CELLMGR_NODE, &cfg_mnc_cmd);
	install_element(CELLMGR_NODE, &cfg_lac_cmd);
	install_element(CELLMGR_NODE, &cfg_isup_pass_cmd);

	/* special commands */
	install_element(ENABLE_NODE, &pcap_set_cmd);
	install_element(ENABLE_NODE, &pcap_set_stop_cmd);
	install_element(ENABLE_NODE, &lnk_block_cmd);
	install_element(ENABLE_NODE, &lnk_unblock_cmd);
	install_element(ENABLE_NODE, &lnk_reset_cmd);
	install_element(ENABLE_NODE, &allow_inject_cmd);

	/* show commands */
	install_element_ve(&show_stats_cmd);
	install_element_ve(&show_linksets_cmd);
	install_element_ve(&show_slc_cmd);

	if (bsc.app != APP_STP) {
		install_element_ve(&show_msc_cmd);
	}
}

const char *openbsc_copyright = "";
