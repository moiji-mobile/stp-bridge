/* VTY code for the osmo-stp */
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
#include <sctp_m2ua.h>
#include <ss7_application.h>
#include <ss7_vty.h>
#include <cellmgr_debug.h>
#include <snmp_mtp.h>

#include <osmocore/talloc.h>
#include <osmocore/gsm48.h>

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

static enum node_type ss7_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case LINK_NODE:
		vty->node = LINKSETS_NODE;
		{
			struct mtp_link *lnk = vty->index;
			vty->index = lnk->set;
			vty->index_sub = &lnk->set->name;
		}
		break;
	case MSC_NODE:
	case APP_NODE:
	case LINKSETS_NODE:
		vty->node = SS7_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
		break;
	case SS7_NODE:
	default:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
		break;
	}

	return vty->node;
}


DEFUN(node_exit, node_exit_cmd,
      "exit", "Exit the current node\n")
{
	ss7_go_parent(vty);
	return CMD_SUCCESS;
}

DEFUN(node_end, node_end_cmd,
      "end", "End the current mode and change to the enable node\n")
{
	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		break;
	default:
		vty_config_unlock(vty);
		vty->node = ENABLE_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
		break;
	}
	return CMD_SUCCESS;
}

static struct vty_app_info vty_info = {
	.name 		= "Cellmgr-ng",
	.version	= VERSION,
	.go_parent_cb	= ss7_go_parent,
};

/* vty code */

static struct cmd_node ss7_node = {
	SS7_NODE,
	"%s(ss7)#",
	1,
};

static struct cmd_node linkset_node = {
	LINKSETS_NODE,
	"%s(linkset)#",
	1,
};

static struct cmd_node link_node = {
	LINK_NODE,
	"%s(link)#",
	1,
};

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(msc)#",
	1,
};

static struct cmd_node app_node = {
	APP_NODE,
	"%s(application)#",
	1,
};

static int dummy_write(struct vty *vty)
{
	return CMD_SUCCESS;
}

static int config_write_ss7(struct vty *vty)
{
	vty_out(vty, "ss7%s", VTY_NEWLINE);
	vty_out(vty, " udp src-port %d%s", bsc->udp_src_port, VTY_NEWLINE);
	vty_out(vty, " m2ua src-port %d%s", bsc->m2ua_src_port, VTY_NEWLINE);
	return CMD_SUCCESS;
}

static void write_link(struct vty *vty, struct mtp_link *link)
{
	const char *name = link->name ? link->name : "";
	struct mtp_udp_link *ulnk;
	struct mtp_m2ua_link *m2ua;

	vty_out(vty, "  link %d%s", link->nr, VTY_NEWLINE);
	vty_out(vty, "   description %s%s", name, VTY_NEWLINE);

	switch (link->type) {
	case SS7_LTYPE_UDP:
		ulnk = (struct mtp_udp_link *) link->data;
		vty_out(vty, "   ss7-transport udp%s", VTY_NEWLINE);
		vty_out(vty, "   udp dest ip %s%s",
			inet_ntoa(ulnk->remote.sin_addr), VTY_NEWLINE);
		vty_out(vty, "   udp dest port %d%s",
			ntohs(ulnk->remote.sin_port), VTY_NEWLINE);
		vty_out(vty, "   udp reset-timeout %d%s",
			ulnk->reset_timeout, VTY_NEWLINE);
		vty_out(vty, "   udp link-index %d%s",
			ulnk->link_index, VTY_NEWLINE);
		break;
	case SS7_LTYPE_M2UA:
		m2ua = (struct mtp_m2ua_link *) link->data;
		vty_out(vty, "   ss7-transport m2ua%s", VTY_NEWLINE);

		if (m2ua->as)
			vty_out(vty, "   m2ua application-server %s%s",
				m2ua->as, VTY_NEWLINE);
		vty_out(vty, "   m2ua link-index %d%s",
			m2ua->link_index, VTY_NEWLINE);
		break;
	case SS7_LTYPE_NONE:
		break;
	}
}

static void write_linkset(struct vty *vty, struct mtp_link_set *set)
{
	const char *name = set->name ? set->name : "";
	struct mtp_link *link;
	int i;

	vty_out(vty, " linkset %d%s", set->nr, VTY_NEWLINE);
	vty_out(vty, "  description %s%s", name, VTY_NEWLINE);
	vty_out(vty, "  mtp3 dpc %d%s", set->dpc, VTY_NEWLINE);
	vty_out(vty, "  mtp3 opc %d%s", set->opc, VTY_NEWLINE);
	vty_out(vty, "  mtp3 ni %d%s", set->ni, VTY_NEWLINE);
	vty_out(vty, "  mtp3 spare %d%s", set->spare, VTY_NEWLINE);
	vty_out(vty, "  mtp3 sltm-once %d%s", set->sltm_once, VTY_NEWLINE);
	vty_out(vty, "  mtp3 timeout t18 %d%s",
		set->timeout_t18, VTY_NEWLINE);
	vty_out(vty, "  mtp3 timeout t20 %d%s",
		set->timeout_t20, VTY_NEWLINE);

	for (i = 0; i < ARRAY_SIZE(set->supported_ssn); ++i) {
		if (!set->supported_ssn[i])
			continue;
		vty_out(vty, "  mtp3 ssn %d%s", i, VTY_NEWLINE);
	}

	llist_for_each_entry(link, &set->links, entry)
		write_link(vty, link);
}

static int config_write_linkset(struct vty *vty)
{
	struct mtp_link_set *set;

	llist_for_each_entry(set, &bsc->linksets, entry)
		write_linkset(vty, set);

	return CMD_SUCCESS;
}

static void write_msc(struct vty *vty, struct msc_connection *msc)
{
	const char *name = msc->name ? msc->name : "";

	vty_out(vty, " msc %d%s", msc->nr, VTY_NEWLINE);
	vty_out(vty, "  description %s%s", name, VTY_NEWLINE);
	vty_out(vty, "  ip %s%s", msc->ip, VTY_NEWLINE);
	vty_out(vty, "  token %s%s", msc->token, VTY_NEWLINE);
	vty_out(vty, "  dscp %d%s", msc->dscp, VTY_NEWLINE);
	vty_out(vty, "  timeout ping %d%s", msc->ping_time, VTY_NEWLINE);
	vty_out(vty, "  timeout pong %d%s", msc->pong_time, VTY_NEWLINE);
	vty_out(vty, "  timeout restart %d%s", msc->msc_time, VTY_NEWLINE);
}

static int config_write_msc(struct vty *vty)
{
	struct msc_connection *msc;

	llist_for_each_entry(msc, &bsc->mscs, entry)
		write_msc(vty, msc);
	return 0;
}

static const char *app_type(enum ss7_app_type type)
{
	switch (type) {
	case APP_NONE:
		return "none";
	case APP_CELLMGR:
		return "msc";
	case APP_RELAY:
		return "relay";
	case APP_STP:
		return "stp";
	default:
		LOGP(DINP, LOGL_ERROR, "Should no be reached.\n");
		return "";
	}
}

static const char *link_type(enum ss7_set_type type)
{
	switch (type) {
	case SS7_SET_LINKSET:
		return "linkset";
	case SS7_SET_MSC:
		return "msc";
	default:
		LOGP(DINP, LOGL_ERROR, "Should no be reached.\n");
		return "";
	}
}

static void write_application(struct vty *vty, struct ss7_application *app)
{
	const char *name = app->name ? app->name : "";

	vty_out(vty, " application %d%s", app->nr, VTY_NEWLINE);
	vty_out(vty, "  description %s%s", name, VTY_NEWLINE);
	vty_out(vty, "  type %s%s", app_type(app->type), VTY_NEWLINE);

	if (app->type == APP_STP)
		vty_out(vty, "  isup-pass-through %d%s", app->isup_pass, VTY_NEWLINE);

	if (app->route_is_set) {
		vty_out(vty, "  route %s %d %s %d%s",
			link_type(app->route_src.type), app->route_src.nr,
			link_type(app->route_dst.type), app->route_dst.nr,
			VTY_NEWLINE);
	}
}

static int config_write_app(struct vty *vty)
{
	struct ss7_application *app;

	llist_for_each_entry(app, &bsc->apps, entry)
		write_application(vty, app);

	return CMD_SUCCESS;
}

DEFUN(cfg_ss7, cfg_ss7_cmd,
      "ss7", "Configure the application\n")
{
	vty->node = SS7_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_ss7_udp_src_port, cfg_ss7_udp_src_port_cmd,
      "udp src-port <1-65535>",
      "UDP related commands\n"
      "Source port for SS7 via UDP transport\n"
      "Port to bind to\n")
{
	bsc->udp_src_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_ss7_m2ua_src_port, cfg_ss7_m2ua_src_port_cmd,
      "m2ua src-port <1-65535>",
      "M2UA related commands\n"
      "Source port for SS7 via M2UA\n"
      "Port to bind to\n")
{
	bsc->m2ua_src_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_ss7_linkset, cfg_ss7_linkset_cmd,
      "linkset <0-100>",
      "Linkset commands\n" "Linkset number\n")
{
	struct mtp_link_set *set;
	int nr;

	nr = atoi(argv[0]);
	if (nr > bsc->num_linksets) {
		vty_out(vty, "%% The next unused Linkset number is %u%s",
			bsc->num_linksets, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (nr == bsc->num_linksets) {
		set = mtp_link_set_alloc(bsc);
	} else
		set = mtp_link_set_num(bsc, nr);

	if (!set) {
		vty_out(vty, "%% Unable to allocate Linkset %u%s",
			nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = LINKSETS_NODE;
	vty->index = set;
	vty->index_sub = &set->name;
	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_mtp3_dpc, cfg_linkset_mtp3_dpc_cmd,
      "mtp3 dpc <0-255>",
      "MTP Level3\n" "Destination Point Code\n" "Point Code\n")
{
	struct mtp_link_set *set = vty->index;
	set->dpc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_mtp3_opc, cfg_linkset_mtp3_opc_cmd,
      "mtp3 opc <0-255>",
      "MTP Level3\n" "Originating Point Code\n" "Point Code\n")
{
	struct mtp_link_set *set = vty->index;
	set->opc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_mtp3_ni, cfg_linkset_mtp3_ni_cmd,
      "mtp3 ni <0-3>",
      "MTP Level3\n" "NI for the address\n" "NI\n")
{
	struct mtp_link_set *set = vty->index;
	set->ni = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_mtp3_spare, cfg_linkset_mtp3_spare_cmd,
      "mtp3 spare <0-3>",
      "MTP Level3\n" "Spare for the address\n" "Spare\n")
{
	struct mtp_link_set *set = vty->index;
	set->spare = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_mtp3_ssn, cfg_linkset_mtp3_ssn_cmd,
      "mtp3 ssn <0-255>",
      "MTP Level3\n" "SSN supported\n" "SSN\n")
{
	struct mtp_link_set *set = vty->index;
	set->supported_ssn[atoi(argv[0])] = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_no_mtp3_ssn, cfg_linkset_no_mtp3_ssn_cmd,
      "no mtp3 ssn <0-255>",
      "MTP Level3\n" "SSN supported\n" "SSN\n")
{
	struct mtp_link_set *set = vty->index;
	set->supported_ssn[atoi(argv[0])] = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_sltm_once, cfg_linkset_sltm_once_cmd,
      "mtp3 sltm-once (0|1)",
      "MTP Level3\n" "Test the link once\n" "Continous testing\n" "Test once\n")
{
	struct mtp_link_set *set = vty->index;
	set->sltm_once = !!atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_t18, cfg_linkset_t18_cmd,
      "mtp3 timeout t18 <0-1000>",
      "MTP Level3\n" "Timeouts\n" "T18 link restart timeout\n" "Seconds\n")
{
	struct mtp_link_set *set = vty->index;
	set->timeout_t18 = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_t20, cfg_linkset_t20_cmd,
      "mtp3 timeout t20 <0-1000>",
      "MTP Level3\n" "Timeouts\n" "T20 link restart timeout\n" "Seconds\n")
{
	struct mtp_link_set *set = vty->index;
	set->timeout_t20 = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_linkset_link, cfg_linkset_link_cmd,
      "link <0-100>",
      "Link\n" "Link number\n")
{
	struct mtp_link_set *set = vty->index;

	struct mtp_link *lnk;
	int nr;

	nr = atoi(argv[0]);
	if (nr > set->nr_links) {
		vty_out(vty, "%% The next unused Link number is %u%s",
			set->nr_links, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (nr == set->nr_links) {
		lnk = mtp_link_alloc(set);
	} else
		lnk = mtp_link_num(set, nr);

	if (!set) {
		vty_out(vty, "%% Unable to allocate Link %u%s",
			nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = LINK_NODE;
	vty->index = lnk;
	vty->index_sub = &lnk->name;
	return CMD_SUCCESS;
}

DEFUN(cfg_link_ss7_transport, cfg_link_ss7_transport_cmd,
      "ss7-transport (none|udp|m2ua)",
      "SS7 transport for the link\n"
      "No transport\n" "MTP over UDP\n" "SCTP M2UA\n")
{
	int wanted = SS7_LTYPE_NONE;
	struct mtp_link *link;

	link = vty->index;

	if (strcmp("udp", argv[0]) == 0)
		wanted = SS7_LTYPE_UDP;
	else if (strcmp("m2ua", argv[0]) == 0)
		wanted = SS7_LTYPE_M2UA;

	if (link->type != wanted && link->type != SS7_LTYPE_NONE) {
		vty_out(vty, "%%Can not change the type of a link.\n");
		return CMD_WARNING;
	}

	switch (wanted) {
	case SS7_LTYPE_UDP:
		link->data = mtp_udp_link_init(link);
		break;
	case SS7_LTYPE_M2UA:
		link->data = mtp_m2ua_link_init(link);
		break;
	case SS7_LTYPE_NONE:
		/* nothing */
		break;
	}

	if (!link->data) {
		vty_out(vty, "Failed to allocate the link type.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_link_udp_dest_ip, cfg_link_udp_dest_ip_cmd,
      "udp dest ip HOST_NAME",
      "UDP Transport\n" "IP\n" "Hostname\n")
{
	struct hostent *hosts;

	struct mtp_link *link = vty->index;
	struct mtp_udp_link *ulnk;

	if (link->type != SS7_LTYPE_UDP) {
		vty_out(vty, "%%This only applies to UDP links.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ulnk = link->data;

	if (ulnk->dest)
		talloc_free(ulnk->dest);
	ulnk->dest = talloc_strdup(ulnk, argv[0]);

	hosts = gethostbyname(ulnk->dest);
	if (!hosts || hosts->h_length < 1 || hosts->h_addrtype != AF_INET) {
		vty_out(vty, "Failed to resolve '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	ulnk->remote.sin_addr = * (struct in_addr *) hosts->h_addr_list[0];

	if (snmp_mtp_peer_name(ulnk->session, ulnk->dest) != 0) {
		vty_out(vty, "%%Failed to open SNMP port on link %d.%s",
			link->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_link_udp_dest_port, cfg_link_udp_dest_port_cmd,
      "udp dest port <1-65535>",
      "UDP Transport\n" "Set the port number\n" "Port\n")
{
	struct mtp_link *link = vty->index;
	struct mtp_udp_link *ulnk;

	if (link->type != SS7_LTYPE_UDP) {
		vty_out(vty, "%%This only applies to UDP links.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ulnk = link->data;
	ulnk->remote.sin_port = htons(atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(cfg_link_udp_reset, cfg_link_udp_reset_cmd,
      "udp reset-timeout <1-65535>",
      "UDP Transport\n" "Reset timeout after a failure\n" "Seconds\n")
{
	struct mtp_link *link = vty->index;
	struct mtp_udp_link *ulnk;

	if (link->type != SS7_LTYPE_UDP) {
		vty_out(vty, "%%This only applies to UDP links.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ulnk = link->data;
	ulnk->reset_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_link_udp_link_index, cfg_link_udp_link_index_cmd,
      "udp link-index <0-65535>",
      "UDP Transport\n" "Link index\n" "Index\n")
{
	struct mtp_link *link = vty->index;
	struct mtp_udp_link *ulnk;

	if (link->type != SS7_LTYPE_UDP) {
		vty_out(vty, "%%This only applies to UDP links.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ulnk = link->data;
	ulnk->link_index = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_link_m2ua_as, cfg_link_m2ua_as_cmd,
      "m2ua application-server NAME",
      "M2UA Transport\n" "Application Server Name\n" "Name\n")
{
	struct mtp_link *link = vty->index;
	struct mtp_m2ua_link *m2ua;

	if (link->type != SS7_LTYPE_M2UA) {
		vty_out(vty, "%%This only applies to M2UA links.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

 	m2ua = link->data;
	if (m2ua->as)
		talloc_free(m2ua->as);
	m2ua->as = talloc_strdup(m2ua, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_link_m2ua_link_index, cfg_link_m2ua_link_index_cmd,
      "m2ua link-index <0-65535>",
      "M2UA Transport\n" "Link index\n" "Index\n")
{
	struct mtp_link *link = vty->index;
	struct mtp_m2ua_link *m2ua;

	if (link->type != SS7_LTYPE_M2UA) {
		vty_out(vty, "%%This only applies to M2UA links.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	m2ua = link->data;
	m2ua->link_index = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_ss7_msc, cfg_ss7_msc_cmd,
      "msc <0-100>",
      "MSC Connection\n" "MSC Number\n")
{
	struct msc_connection *msc;
	int nr;

	nr = atoi(argv[0]);
	if (nr > bsc->num_mscs) {
		vty_out(vty, "%% The next unused MSC number is %u%s",
			bsc->num_mscs, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (nr == bsc->num_mscs) {
		msc = msc_connection_create(bsc, 1);
	} else
		msc = msc_connection_num(bsc, nr);

	if (!msc) {
		vty_out(vty, "%% Unable to allocate MSC %u%s",
			nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = MSC_NODE;
	vty->index = msc;
	vty->index_sub = &msc->name;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_ip, cfg_msc_ip_cmd,
      "ip ADDR",
      "IP Address of the MSC\n" "Address\n")
{
	struct hostent *hosts;
	struct msc_connection *msc;

	msc = vty->index;
	hosts = gethostbyname(argv[0]);
	if (!hosts || hosts->h_length < 1 || hosts->h_addrtype != AF_INET) {
		vty_out(vty, "Failed to resolve '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (msc->ip)
		talloc_free(msc->ip);

	msc->ip = talloc_strdup(msc,
			inet_ntoa(*((struct in_addr *) hosts->h_addr_list[0])));
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_token, cfg_msc_token_cmd,
      "token TOKEN",
      "Token for the MSC\n" "The token\n")
{
	struct msc_connection *msc = vty->index;

	if (msc->token)
		talloc_free(msc->token);
	msc->token = talloc_strdup(msc, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_dscp, cfg_msc_dscp_cmd,
      "dscp <0-255>",
      "DSCP for the IP Connection\n" "Nr\n")
{
	struct msc_connection *msc = vty->index;
	msc->dscp = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_timeout_ping, cfg_msc_timeout_ping_cmd,
      "timeout ping <1-65535>",
      "Timeout commands\n" "Time between pings\n" "Seconds\n")
{
	struct msc_connection *msc = vty->index;
	msc->ping_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_timeout_pong, cfg_msc_timeout_pong_cmd,
      "timeout pong <1-65535>",
      "Timeout commands\n" "Time between pongs\n" "Seconds\n")
{
	struct msc_connection *msc = vty->index;
	msc->pong_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_timeout_restart, cfg_msc_timeout_restart_cmd,
      "timeout restart <1-65535>",
      "Timeout commands\n" "Time between restarts\n" "Seconds\n")
{
	struct msc_connection *msc = vty->index;
	msc->msc_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_ss7_app, cfg_ss7_app_cmd,
      "application <0-100>",
      "Application Commands\n" "Number\n")
{
	struct ss7_application *app;
	int nr;

	nr = atoi(argv[0]);
	if (nr > bsc->num_apps) {
		vty_out(vty, "%% The next unused Application number is %u%s",
			bsc->num_apps, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (nr == bsc->num_apps) {
		app = ss7_application_alloc(bsc);
	} else
		app = ss7_application_num(bsc, nr);

	if (!app) {
		vty_out(vty, "%% Unable to allocate Application %u%s",
			nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = APP_NODE;
	vty->index = app;
	vty->index_sub = &app->name;
	return CMD_SUCCESS;
}

DEFUN(cfg_app_type, cfg_app_type_cmd,
      "type (none|stp|relay|msc)",
      "Type of Application\n"
      "No type\n" "Signalling Transfer Point\n"
      "Relay SCCP/ISUP messages\n" "MSC connector with state\n")
{
	enum ss7_app_type type;
	struct ss7_application *app = vty->index;

	switch (argv[0][0]) {
	case 'm':
		type = APP_CELLMGR;
		break;
	case 'r':
		type = APP_RELAY;
		break;
	case 's':
		type = APP_STP;
		break;
	default:
	case 'n':
		type = APP_NONE;
		break;
	}

	if (app->type != APP_NONE && app->type != type) {
		vty_out(vty, "The type can not be changed at runtime on app %d.%s",
			app->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	app->type = type;
	return CMD_SUCCESS;
}

DEFUN(cfg_app_isup_pass, cfg_app_isup_pass_cmd,
      "isup-pass-through (0|1)",
      "Pass all ISUP messages\n" "Handle some ISUP locally\n" "Pass all messages\n")
{
	struct ss7_application *app = vty->index;

	if (app->type != APP_STP) {
		vty_out(vty, "%%Need to use the 'stp' app for this option on app %d.%s",
			app->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	ss7_application_pass_isup(app, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(cfg_app_route, cfg_app_route_cmd,
      "route linkset <0-100> msc <0-100>",
      "Routing commands\n" "Source Linkset\n" "Linkset Nr\n"
      "Dest MSC\n" "MSC Nr\n")
{
	struct ss7_application *app = vty->index;

	if (app->type != APP_CELLMGR && app->type != APP_RELAY) {
		vty_out(vty, "The app type needs to be 'relay' or 'msc'.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ss7_application_setup(app, app->type,
				  SS7_SET_LINKSET, atoi(argv[0]),
				  SS7_SET_MSC, atoi(argv[1])) != 0) {
		vty_out(vty, "Failed to route linkset %d to msc %d.%s",
			atoi(argv[0]), atoi(argv[1]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_app_route_ls, cfg_app_route_ls_cmd,
      "route linkset <0-100> linkset <0-100>",
      "Routing commands\n" "Source Linkset\n" "Linkset Nr\n"
      "Dest Linkset\n" "Linkset Nr\n" )
{
	struct ss7_application *app = vty->index;

	if (app->type != APP_STP) {
		vty_out(vty, "The app type needs to be 'stp'.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ss7_application_setup(app, app->type,
				  SS7_SET_LINKSET, atoi(argv[0]),
				  SS7_SET_LINKSET, atoi(argv[1])) != 0) {
		vty_out(vty, "Failed to route linkset %d to linkset %d.%s",
			atoi(argv[0]), atoi(argv[1]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

static void install_defaults(int node)
{
	install_default(node);
	install_element(node, &node_exit_cmd);
	install_element(node, &node_end_cmd);
	install_element(node, &cfg_description_cmd);
	install_element(node, &cfg_no_description_cmd);
}

extern void cell_vty_init_cmds(void);
void cell_vty_init(void)
{
	cmd_init(1);
	vty_init(&vty_info);
	logging_vty_add_cmds();

	install_element(CONFIG_NODE, &cfg_ss7_cmd);
	install_node(&ss7_node, config_write_ss7);
	install_defaults(SS7_NODE);
	install_element(SS7_NODE, &cfg_ss7_udp_src_port_cmd);
	install_element(SS7_NODE, &cfg_ss7_m2ua_src_port_cmd);

	install_element(SS7_NODE, &cfg_ss7_linkset_cmd);
	install_node(&linkset_node, config_write_linkset);
	install_defaults(LINKSETS_NODE);
	install_element(LINKSETS_NODE, &cfg_linkset_mtp3_dpc_cmd);
	install_element(LINKSETS_NODE, &cfg_linkset_mtp3_opc_cmd);
	install_element(LINKSETS_NODE, &cfg_linkset_mtp3_ni_cmd);
	install_element(LINKSETS_NODE, &cfg_linkset_mtp3_spare_cmd);
	install_element(LINKSETS_NODE, &cfg_linkset_mtp3_ssn_cmd);
	install_element(LINKSETS_NODE, &cfg_linkset_no_mtp3_ssn_cmd);
	install_element(LINKSETS_NODE, &cfg_linkset_sltm_once_cmd);
	install_element(LINKSETS_NODE, &cfg_linkset_t18_cmd);
	install_element(LINKSETS_NODE, &cfg_linkset_t20_cmd);

	install_element(LINKSETS_NODE, &cfg_linkset_link_cmd);
	install_node(&link_node, dummy_write);
	install_defaults(LINK_NODE);
	install_element(LINK_NODE, &cfg_link_ss7_transport_cmd);
	install_element(LINK_NODE, &cfg_link_udp_dest_ip_cmd);
	install_element(LINK_NODE, &cfg_link_udp_dest_port_cmd);
	install_element(LINK_NODE, &cfg_link_udp_reset_cmd);
	install_element(LINK_NODE, &cfg_link_udp_link_index_cmd);
	install_element(LINK_NODE, &cfg_link_m2ua_as_cmd);
	install_element(LINK_NODE, &cfg_link_m2ua_link_index_cmd);

	install_element(SS7_NODE, &cfg_ss7_msc_cmd);
	install_node(&msc_node, config_write_msc);
	install_defaults(MSC_NODE);
	install_element(MSC_NODE, &cfg_msc_ip_cmd);
	install_element(MSC_NODE, &cfg_msc_token_cmd);
	install_element(MSC_NODE, &cfg_msc_dscp_cmd);
	install_element(MSC_NODE, &cfg_msc_timeout_ping_cmd);
	install_element(MSC_NODE, &cfg_msc_timeout_pong_cmd);
	install_element(MSC_NODE, &cfg_msc_timeout_restart_cmd);

	install_element(SS7_NODE, &cfg_ss7_app_cmd);
	install_node(&app_node, config_write_app);
	install_defaults(APP_NODE);
	install_element(APP_NODE, &cfg_app_type_cmd);
	install_element(APP_NODE, &cfg_app_isup_pass_cmd);
	install_element(APP_NODE, &cfg_app_route_cmd);
	install_element(APP_NODE, &cfg_app_route_ls_cmd);

	cell_vty_init_cmds();
}

const char *openbsc_copyright = "";
