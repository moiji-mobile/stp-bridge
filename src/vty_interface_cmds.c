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

#include <osmocore/rate_ctr.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/vty.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

extern struct bsc_data *bsc;

static void dump_stats(struct vty *vty, struct mtp_link_set *set)
{
	struct mtp_link *link;

	vty_out(vty, "Linkset name: %s opc: %d%s", set->name, set->opc, VTY_NEWLINE);
	vty_out_rate_ctr_group(vty, " ", set->ctrg);

	llist_for_each_entry(link, &set->links, entry) {
		vty_out(vty, " Link %d%s", link->nr, VTY_NEWLINE);
		vty_out_rate_ctr_group(vty, "  ", link->ctrg);
	}
}

DEFUN(show_stats, show_stats_cmd,
      "show statistics",
      SHOW_STR "Display Linkset statistics\n")
{
	struct mtp_link_set *set;

	llist_for_each_entry(set, &bsc->linksets, entry)
		dump_stats(vty, set);

	return CMD_SUCCESS;
}

static void dump_state(struct vty *vty, struct mtp_link_set *set)
{
	struct mtp_link *link;

	if (!set) {
		vty_out(vty, "LinkSet for %s is not configured.%s", set->name, VTY_NEWLINE);
		return;
	}

	vty_out(vty, "LinkSet for %s is %s, remote sccp is %s.%s",
		set->name,
		set->available == 0 ? "not available" : "available",
		set->sccp_up == 0? "not established" : "established",
		VTY_NEWLINE);

	llist_for_each_entry(link, &set->links, entry) {
		if (link->blocked)
			vty_out(vty, " Link %d is blocked.%s",
				link->nr, VTY_NEWLINE);
		else
			vty_out(vty, " Link %d is %s.%s",
				link->nr,
				link->available == 0 ? "not available" : "available",
				VTY_NEWLINE);
	}
}

DEFUN(show_linksets, show_linksets_cmd,
      "show link-sets",
      SHOW_STR "Display current state of linksets\n")
{
	struct mtp_link_set *set;

	llist_for_each_entry(set, &bsc->linksets, entry)
		dump_state(vty, set);
	return CMD_SUCCESS;
}

DEFUN(show_msc, show_msc_cmd,
      "show msc",
      SHOW_STR "Display the status of the MSC\n")
{
	struct msc_connection *msc = msc_connection_num(bsc, 0);

	if (!msc) {
		vty_out(vty, "%%No MSC Connection defined in this app.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "MSC link is %s and had %s.%s",
		msc->msc_link_down == 0 ? "up" : "down",
		msc->first_contact == 1 ? "no contact" : "contact",
		VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_slc, show_slc_cmd,
      "show link-set <0-100> slc",
      SHOW_STR "LinkSet\n" "Linkset nr\n" "SLS to SLC\n")
{
	struct mtp_link_set *set = NULL;
	int i;

	set = mtp_link_set_num(bsc, atoi(argv[0]));

	if (!set) {
		vty_out(vty, "Failed to find linkset.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "LinkSet for %s.%s", argv[0], VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(set->slc); ++i) {
		if (set->slc[i])
			vty_out(vty, " SLC[%.2d] is on link %d.%s",
				i, set->slc[i]->nr, VTY_NEWLINE);
		else
			vty_out(vty, " SLC[%d] is down.%s",
				i, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(pcap_set, pcap_set_cmd,
      "trace-pcap <0-100> NAME FILE",
      "Trace to a PCAP file\n" "Linkset nr.\n"
      "Trace Linkset\n" "Filename to trace\n")
{
	struct mtp_link_set *set = NULL;

	set = mtp_link_set_num(bsc, atoi(argv[0]));

	if (!set) {
		vty_out(vty, "Failed to find linkset.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}


	if (set->pcap_fd >= 0 && bsc->pcap_fd != set->pcap_fd)
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
      "trace-pcap <0-100> NAME stop",
      "Trace to a PCAP file\n" "Linkset nr\n"
      "Trace Linkset\n" "Stop the tracing\n")
{
	struct mtp_link_set *set = NULL;

	set = mtp_link_set_num(bsc, atoi(argv[0]));

	if (!set) {
		vty_out(vty, "Failed to find linkset.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (set->pcap_fd >= 0 && bsc->pcap_fd != set->pcap_fd)
		close(set->pcap_fd);
	set->pcap_fd = -1;
	return CMD_SUCCESS;
}

#define FIND_LINK(vty, set_no, nr) ({						\
	struct mtp_link_set *set = NULL;					\
	struct mtp_link *link = NULL;						\
	set = mtp_link_set_num(bsc, set_no);					\
	if (!set) {								\
		vty_out(vty, "Unknown Linkset nr %d.%s", set_no, VTY_NEWLINE);	\
		return CMD_WARNING;						\
	}									\
	link = mtp_link_num(set, nr);						\
	if (!link) {								\
		vty_out(vty, "Can not find link %d.%s", nr, VTY_NEWLINE);	\
		return CMD_WARNING;						\
	}									\
	link; })

#define LINK_STR "Operations on the link\n"					\
		 "Linkset number\n"						\
		 "Link number\n"

DEFUN(lnk_block, lnk_block_cmd,
      "link <0-100> <0-15> block",
      LINK_STR "Block it\n")
{
	struct mtp_link *link = FIND_LINK(vty, atoi(argv[0]), atoi(argv[1]));
	mtp_link_block(link);
	return CMD_SUCCESS;
}

DEFUN(lnk_unblock, lnk_unblock_cmd,
      "link <0-100> <0-15> unblock",
      LINK_STR "Unblock it\n")
{
	struct mtp_link *link = FIND_LINK(vty, atoi(argv[0]), atoi(argv[1]));
	mtp_link_unblock(link);
	return CMD_SUCCESS;
}

DEFUN(lnk_reset, lnk_reset_cmd,
      "link <0-100> <0-15> reset",
      LINK_STR "Reset it\n")
{
	struct mtp_link *link = FIND_LINK(vty, atoi(argv[0]), atoi(argv[1]));
	mtp_link_failure(link);
	return CMD_SUCCESS;
}

DEFUN(allow_inject, allow_inject_cmd,
      "allow-inject (0|1)",
      "Allow to inject messages\n" "Disable\n" "Enable\n")
{
	bsc->allow_inject = atoi(argv[0]);
	return CMD_SUCCESS;
}

void cell_vty_init_cmds(void)
{
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

	install_element_ve(&show_msc_cmd);
}
