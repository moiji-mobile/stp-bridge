/* Extra vty handling for the SS7 code */
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

#include <mgcp_ss7.h>
#include <ss7_vty.h>

#include <mgcp/mgcp.h>

#include <stdlib.h>

extern struct mgcp_config *g_cfg;

static struct vty_app_info vty_info = {
	.name 		= "mgcp_ss7",
	.version	= "0.0.1",
	.go_parent_cb	= NULL,
};

void logging_vty_add_cmds(void);

DEFUN(cfg_mgcp_configure, cfg_mgcp_configure_cmd,
      "configure-trunks (0|1)",
      "Reconfigure the Trunk Configuration\n" "Reconfigure\n" "Keep\n")
{
	g_cfg->configure_trunks = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_vad, cfg_mgcp_vad_cmd,
      "vad (enabled|disabled)",
      "Enable the Voice Activity Detection\n"
      "Enable\n" "Disable\n")
{
	if (argv[0][0] == 'e')
		g_cfg->trunk.vad_enabled = 1;
	else
		g_cfg->trunk.vad_enabled = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_realloc, cfg_mgcp_realloc_cmd,
      "force-realloc (0|1)",
      "Force the reallocation of an endpoint\n"
      "Disable\n" "Enable\n")
{
	g_cfg->trunk.force_realloc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_inp_dig_gain, cfg_mgcp_inp_dig_gain_cmd,
      "input-digital-gain <0-62>",
      "Static Digital Input Gain\n"
      "Gain value")
{
	g_cfg->trunk.digital_inp_gain = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_out_dig_gain, cfg_mgcp_out_dig_gain_cmd,
      "outut-digital-gain <0-62>",
      "Static Digital Output Gain\n"
      "Gain value")
{
	g_cfg->trunk.digital_out_gain = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_upstr_agc, cfg_mgcp_upstr_agc_cmd,
      "upstream-automatic-gain (0|1)",
      "Enable automatic gain control on upstream\n"
      "Disable\n" "Enabled\n")
{
	g_cfg->trunk.upstr_agc_enbl = argv[0][0] == '1';
	return CMD_SUCCESS;
}

DEFUN(cfg_mgc_upstr_adp, cfg_mgcp_upstr_adp_cmd,
      "upstream-adaptiton-rate <1-128>",
      "Set the adaption rate in (dB/sec) * 10\n"
      "Range\n")
{
	g_cfg->trunk.upstr_adp_rate = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_upstr_max_gain, cfg_mgcp_upstr_max_gain_cmd,
      "upstream-max-applied-gain <0-49>",
      "Maximum applied gain from -31db to 18db\n"
      "Gain level\n")
{
	g_cfg->trunk.upstr_max_gain = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_upstr_target, cfg_mgcp_upstr_target_cmd,
      "upstream-target-level <6-37>",
      "Set the desired level in db\n"
      "Desired lievel\n")
{
	g_cfg->trunk.upstr_target_lvl = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_dwnstr_agc, cfg_mgcp_dwnstr_agc_cmd,
      "downstream-automatic-gain (0|1)",
      "Enable automatic gain control on downstream\n"
      "Disable\n" "Enabled\n")
{
	g_cfg->trunk.dwnstr_agc_enbl = argv[0][0] == '1';
	return CMD_SUCCESS;
}

DEFUN(cfg_mgc_dwnstr_adp, cfg_mgcp_dwnstr_adp_cmd,
      "downstream-adaptation-rate <1-128>",
      "Set the adaption rate in (dB/sec) * 10\n"
      "Range\n")
{
	g_cfg->trunk.dwnstr_adp_rate = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_dwnstr_max_gain, cfg_mgcp_dwnstr_max_gain_cmd,
      "downstream-max-applied-gain <0-49>",
      "Maximum applied gain from -31db to 18db\n"
      "Gain level\n")
{
	g_cfg->trunk.dwnstr_max_gain = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_dwnstr_target, cfg_mgcp_dwnstr_target_cmd,
      "downstream-target-level <6-37>",
      "Set the desired level in db\n"
      "Desired lievel\n")
{
	g_cfg->trunk.dwnstr_target_lvl = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_endp_offset, cfg_mgcp_endp_offset_cmd,
      "endpoint-offset <-60-60>",
      "Offset to the CIC map\n" "Value to set\n")
{
	g_cfg->trunk.endp_offset = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_target_trunk, cfg_mgcp_target_trunk_cmd,
      "target-trunk-start <1-24>",
      "Map the virtual trunk to start here\n" "Trunk Nr\n")
{
	g_cfg->trunk.target_trunk_start = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_vad, cfg_trunk_vad_cmd,
      "vad (enabled|disabled)",
      "Enable the Voice Activity Detection\n"
      "Enable\n" "Disable\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	if (argv[0][0] == 'e')
		trunk->vad_enabled = 1;
	else
		trunk->vad_enabled = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_realloc, cfg_trunk_realloc_cmd,
      "force-realloc (0|1)",
      "Force the reallocation of an endpoint\n"
      "Disable\n" "Enable\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->force_realloc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_inp_dig_gain, cfg_trunk_inp_dig_gain_cmd,
      "input-digital-gain <0-62>",
      "Static Digital Input Gain\n"
      "Gain value")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->digital_inp_gain = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_out_dig_gain, cfg_trunk_out_dig_gain_cmd,
      "outut-digital-gain <0-62>",
      "Static Digital Output Gain\n"
      "Gain value")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->digital_out_gain = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_upstr_agc, cfg_trunk_upstr_agc_cmd,
      "upstream-automatic-gain (0|1)",
      "Enable automatic gain control on upstream\n"
      "Disable\n" "Enabled\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->upstr_agc_enbl = argv[0][0] == '1';
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_upstr_adp, cfg_trunk_upstr_adp_cmd,
      "upstream-adaptiton-rate <1-128>",
      "Set the adaption rate in (dB/sec) * 10\n"
      "Range\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->upstr_adp_rate = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_upstr_max_gain, cfg_trunk_upstr_max_gain_cmd,
      "upstream-max-applied-gain <0-49>",
      "Maximum applied gain from -31db to 18db\n"
      "Gain level\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->upstr_max_gain = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_upstr_target, cfg_trunk_upstr_target_cmd,
      "upstream-target-level <6-37>",
      "Set the desired level in db\n"
      "Desired lievel\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->upstr_target_lvl = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_dwnstr_agc, cfg_trunk_dwnstr_agc_cmd,
      "downstream-automatic-gain (0|1)",
      "Enable automatic gain control on downstream\n"
      "Disable\n" "Enabled\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->dwnstr_agc_enbl = argv[0][0] == '1';
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_dwnstr_adp, cfg_trunk_dwnstr_adp_cmd,
      "downstream-adaptation-rate <1-128>",
      "Set the adaption rate in (dB/sec) * 10\n"
      "Range\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->dwnstr_adp_rate = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_dwnstr_max_gain, cfg_trunk_dwnstr_max_gain_cmd,
      "downstream-max-applied-gain <0-49>",
      "Maximum applied gain from -31db to 18db\n"
      "Gain level\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->dwnstr_max_gain = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_dwnstr_target, cfg_trunk_dwnstr_target_cmd,
      "downstream-target-level <6-37>",
      "Set the desired level in db\n"
      "Desired lievel\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->dwnstr_target_lvl = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_endp_offset, cfg_trunk_endp_offset_cmd,
      "endpoint-offset <-60-60>",
      "Offset to the CIC map\n" "Value to set\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->endp_offset = atoi(argv[0]);
	return CMD_SUCCESS;
}

void mgcp_write_extra(struct vty *vty, struct mgcp_config *cfg)
{
	vty_out(vty, "  configure-trunks %d%s",
		cfg->configure_trunks, VTY_NEWLINE);
	vty_out(vty, "  force-realloc %d%s",
		cfg->trunk.force_realloc, VTY_NEWLINE);
	vty_out(vty, "  vad %s%s",
		cfg->trunk.vad_enabled ? "enabled" : "disabled", VTY_NEWLINE);
	vty_out(vty, "  input-digital-gain %d%s",
		cfg->trunk.digital_inp_gain, VTY_NEWLINE);
	vty_out(vty, "  output-digital-gain %d%s",
		cfg->trunk.digital_out_gain, VTY_NEWLINE);
	vty_out(vty, "  upstream-automatic-gain %d%s",
		cfg->trunk.upstr_agc_enbl, VTY_NEWLINE);
	vty_out(vty, "  upstream-adaptation-rate %d%s",
		cfg->trunk.upstr_adp_rate, VTY_NEWLINE);
	vty_out(vty, "  upstream-max-applied-gain %d%s",
		cfg->trunk.upstr_max_gain, VTY_NEWLINE);
	vty_out(vty, "  upstream-target-level %d%s",
		cfg->trunk.upstr_target_lvl, VTY_NEWLINE);
	vty_out(vty, "  downstream-automatic-gain %d%s",
		cfg->trunk.dwnstr_agc_enbl, VTY_NEWLINE);
	vty_out(vty, "  downstream-adaptation-rate %d%s",
		cfg->trunk.dwnstr_adp_rate, VTY_NEWLINE);
	vty_out(vty, "  downstream-max-applied-gain %d%s",
		cfg->trunk.dwnstr_max_gain, VTY_NEWLINE);
	vty_out(vty, "  downstream-target-level %d%s",
		cfg->trunk.dwnstr_target_lvl, VTY_NEWLINE);
	vty_out(vty, "  endpoint-offset %d%s",
		cfg->trunk.endp_offset, VTY_NEWLINE);
	vty_out(vty, "  target-trunk-start %d%s",
		cfg->trunk.target_trunk_start, VTY_NEWLINE);
}

void mgcp_write_trunk_extra(struct vty *vty, struct mgcp_trunk_config *trunk)
{
	vty_out(vty, "   force-realloc %d%s",
		trunk->force_realloc, VTY_NEWLINE);
	vty_out(vty, "   vad %s%s",
		trunk->vad_enabled ? "enabled" : "disabled", VTY_NEWLINE);
	vty_out(vty, "   input-digital-gain %d%s",
		trunk->digital_inp_gain, VTY_NEWLINE);
	vty_out(vty, "   output-digital-gain %d%s",
		trunk->digital_out_gain, VTY_NEWLINE);
	vty_out(vty, "   upstream-automatic-gain %d%s",
		trunk->upstr_agc_enbl, VTY_NEWLINE);
	vty_out(vty, "   upstream-adaptation-rate %d%s",
		trunk->upstr_adp_rate, VTY_NEWLINE);
	vty_out(vty, "   upstream-max-applied-gain %d%s",
		trunk->upstr_max_gain, VTY_NEWLINE);
	vty_out(vty, "   upstream-target-level %d%s",
		trunk->upstr_target_lvl, VTY_NEWLINE);
	vty_out(vty, "   downstream-automatic-gain %d%s",
		trunk->dwnstr_agc_enbl, VTY_NEWLINE);
	vty_out(vty, "   downstream-adaptation-rate %d%s",
		trunk->dwnstr_adp_rate, VTY_NEWLINE);
	vty_out(vty, "   downstream-max-applied-gain %d%s",
		trunk->dwnstr_max_gain, VTY_NEWLINE);
	vty_out(vty, "   downstream-target-level %d%s",
		trunk->dwnstr_target_lvl, VTY_NEWLINE);
	vty_out(vty, "   endpoint-offset %d%s",
		trunk->endp_offset, VTY_NEWLINE);
}


void mgcp_mgw_vty_init(void)
{
	cmd_init(1);
	vty_init(&vty_info);
	logging_vty_add_cmds();
	mgcp_vty_init();

	install_element(MGCP_NODE, &cfg_mgcp_configure_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_vad_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_realloc_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_inp_dig_gain_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_out_dig_gain_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_upstr_agc_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_upstr_adp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_upstr_max_gain_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_upstr_target_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_dwnstr_agc_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_dwnstr_adp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_dwnstr_max_gain_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_dwnstr_target_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_endp_offset_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_target_trunk_cmd);

	install_element(TRUNK_NODE, &cfg_trunk_vad_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_realloc_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_inp_dig_gain_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_out_dig_gain_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_upstr_agc_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_upstr_adp_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_upstr_max_gain_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_upstr_target_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_dwnstr_agc_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_dwnstr_adp_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_dwnstr_max_gain_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_dwnstr_target_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_endp_offset_cmd);
}


const char *openbsc_copyright = "";
