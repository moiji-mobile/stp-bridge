/* Use the UniPorte library to allocate endpoints */
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

#include <mgcp_ss7.h>
#include <mgcp/mgcp.h>
#include <mgcp/mgcp_internal.h>

#include <cellmgr_debug.h>

#include <osmocore/select.h>
#include <osmocore/talloc.h>
#include <osmocore/timer.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>

/* uniporte includes */
#ifndef NO_UNIPORTE
#include <UniPorte.h>
#include <BusMastHostApi.h>
#include <MtnSa.h>
#include <SystemLayer.h>
#include <PredefMobs.h>
#endif

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>

static struct log_target *stderr_target;
static char *config_file = "mgcp_mgw.cfg";
static int exit_on_failure = 0;

#define TO_MGW_PORT(no) (no-1)
#define FROM_MGW_PORT(no) (no+1)

static struct mgcp_ss7 *s_ss7;
static struct mgcp_config *g_cfg;
static int s_vad_enabled = 1;

struct mgcp_ss7_endpoint {
	unsigned int port;
	int block;
};

static void mgcp_ss7_endp_free(struct mgcp_ss7* ss7, int endp);
static void mgcp_ss7_do_exec(struct mgcp_ss7 *mgcp, uint8_t type, uint32_t port, uint32_t param);
static void mgcp_mgw_vty_init();

static void check_exit(int status)
{
	if (exit_on_failure && status == 21) {
		LOGP(DMGCP, LOGL_ERROR, "Failure detected with the MGW. Exiting.\n");
      		exit(-1);
	}
}

#ifndef NO_UNIPORTE
static void Force_Poll( int milliseconds )
{
  int timeout = 0;
  unsigned long startTime;

  startTime = SysLyrGetTime();

  /*  Loop until the specified number of milliseconds
   * have elapsed.
   */
  do {
    MtnSaPoll();
    SysLyrSleep( 20 );
  } while ((SysLyrGetTime()-startTime)<(unsigned long)milliseconds);
  return;
}

static char eventName[Event_TELEMETRY_DATA + 1][128] = {
	{ "Event_NOT_READY" },
	{ "Event_READY" },
	{ "Event_ANSWER" },
	{ "Event_OUTGOING_CALL" },
	{ "Event_ABORT" },
	{ "Event_CONNECT" },
	{ "Event_DISCONNECT" },
	{ "Event_MANAGED_OBJECT_GET_COMPLETE" },
	{ "Event_MANAGED_OBJECT_GET_AND_CLEAR_COMPLETE" },
	{ "Event_MANAGED_OBJECT_SET_COMPLETE" },
	{ "Event_MANAGED_OBJECT_TRAP" },
	{ "Event_PREDEF_MOB_SET_COMPLETE" },
	{ "Event_PREDEF_MOB_GET_COMPLETE" },
	{ "Event_USER_MOB_DEFINE_COMPLETE" },
	{ "Event_USER_MOB_SET_COMPLETE" },
	{ "Event_USER_MOB_GET_COMPLETE" },
	{ "Event_RECEIVE_DATA" },
	{ "Event_SEND_COMPLETE" },
	{ "Event_TDM_CONNECT_COMPLETE" },
	{ "Event_LOG" },
	{ "Event_DEVICE_IN_CONTACT" },
	{ "Event_DEVICE_MANAGED" },
	{ "Event_DEVICE_OUT_OF_CONTACT" },
	{ "Event_TELEMETRY_DATA" } };

static char stateName[PortState_END_OF_ENUM][128] = {
   { "PortState_IDLE" },
   { "PortState_SIGNALING" },
   { "PortState_INITIATING" },
   { "PortState_LINK" },
   { "PortState_TRAINING" },
   { "PortState_EC_NEGOTIATING" },
   { "PortState_DATA" },
   { "PortState_RESYNCING" },
   { "PortState_FAX" },
   { "PortState_COMMAND_ESCAPE" },
   { "PortState_TERMINATING" },
   { "PortState_VOICE" },
   { "PortState_PORT_RESET" },
   { "PortState_DSP_RESET" },
   { "PortState_ALLOCATED" },
   { "PortState_OUT_OF_SERVICE" },
   { "PortState_RECONFIGURE" },  
   { "PortState_ON_HOLD" } };
static int uniporte_events(unsigned long port, EventTypeT event,
			   void *event_data,  unsigned long event_data_length ) {
  char text[128];
  ManObjectInfoPtr info;
  DataReceiveInfoPtr dataInfo;
  int i;
  ToneDetectionPtr tones;


  /*  Don't print output when we receive data or complete
   * sending data.  That would be too verbose.
   */
  if (event==Event_DEVICE_MANAGED) {
     MtnSaSetManObject(0, ChannelType_ETHERNET, ManObj_C_MOE_COMM_LOSS_RESET_DELAY ,
                        10, 0);
  }  
  else if (event==Event_MANAGED_OBJECT_TRAP ) {
    info = (ManObjectInfoPtr)event_data;
    if (info->trapId == Trap_PORT_STATE_CHANGE) {
      sprintf(text, "Port #%ld, Change to state %s", port, stateName[info->value]);
      puts(text);

      /* update the mgcp state */
      int mgcp_endp = FROM_MGW_PORT(port);
      if (s_ss7->mgw_end[mgcp_endp].block != 1)
         fprintf(stderr, "State change on a non blocked port. ERROR.\n");
      s_ss7->mgw_end[mgcp_endp].block = 0;
    }
  }
  else if ( event == Event_MANAGED_OBJECT_SET_COMPLETE ) {
    info = (ManObjectInfoPtr)event_data;

    sprintf(text, "Object %d value %d status %d", info->object, info->value, 
            info->status );
    puts(text);
    check_exit(info->status);
  }
   else if ( ( event == Event_USER_MOB_SET_COMPLETE ) ||
			    ( event == Event_USER_MOB_DEFINE_COMPLETE ) )
   {
		info = (ManObjectInfoPtr)event_data;

		sprintf( text, "Mob ID %d status %d", info->MOBId, info->status );
		puts(text);
		check_exit(info->status);
   }
   else if ( event == Event_USER_MOB_GET_COMPLETE )
   {
		info = (ManObjectInfoPtr)event_data;

		sprintf( text, "Mob ID %d status %d", info->MOBId, info->status );
		puts(text);
		check_exit(info->status);
   }
   else if (event == Event_CONNECT)
   {
	   sprintf(text, "Port %d connected",port );
   }
   else if (event == Event_PREDEF_MOB_GET_COMPLETE)
   {
		info = (ManObjectInfoPtr)event_data;

		sprintf(text, "Mob ID %d status %d", info->MOBId, info->status );
		puts(text);
		check_exit(info->status);
   }

   return( 0 );
}

static int initialize_uniporte(struct mgcp_ss7 *mgcp)
{	
	ProfileT profile;
	unsigned long mgw_address;
	int rc;

	LOGP(DMGCP, LOGL_NOTICE, "Initializing MGW on %s\n", mgcp->cfg->bts_ip);

 	MtnSaSetEthernetOnly();
	rc = MtnSaStartup(uniporte_events);
	if (rc != 0)
		LOGP(DMGCP, LOGL_ERROR, "Failed to startup the MGW.\n");
	SysEthGetHostAddress(mgcp->cfg->bts_ip, &mgw_address);	
	rc = MtnSaRegisterEthernetDevice(mgw_address, 0);
	if (rc != 0)
		LOGP(DMGCP, LOGL_ERROR, "Failed to register ethernet.\n");
	Force_Poll(2000);
	MtnSaTakeOverDevice(0);
	Force_Poll(2000);
	MtnSaSetReceiveTraps(1);
	MtnSaSetTransparent();

	/* change the voice profile to AMR */
	MtnSaGetProfile(ProfileType_VOICE, 0, &profile);
	profile.countryCode = CountryCode_INTERNAT_ALAW; 
	MtnSaSetProfile(ProfileType_VOICE, 0, &profile);

	if (MtnSaGetPortCount() == 0)
		return -1;

	return 0;
}


static void* start_uniporte(void *_ss7) {
	struct llist_head blocked;
	struct mgcp_ss7_cmd *cmd, *tmp;
	struct mgcp_ss7 *ss7 = _ss7;

	s_ss7 = ss7;

	if (initialize_uniporte(ss7) != 0) {
		fprintf(stderr, "Failed to create Uniporte.\n");
		exit(-1);
		return 0; 
	}

	fprintf(stderr, "Created the MGCP processing thread.\n");
	INIT_LLIST_HEAD(&blocked);
	for (;;) {
		thread_swap(ss7->cmd_queue);
start_over:
		/* handle items that are currently blocked */
		llist_for_each_entry_safe(cmd, tmp, &blocked, entry) {
			if (ss7->mgw_end[cmd->port].block)
				continue;

			mgcp_ss7_do_exec(ss7, cmd->type, cmd->port, cmd->param);
			llist_del(&cmd->entry);
			free(cmd);

			/* We might have unblocked something, make sure we operate in order */
    			MtnSaPoll();
			goto start_over;
		}

		llist_for_each_entry_safe(cmd, tmp, ss7->cmd_queue->main_head, entry) {
			if (ss7->mgw_end[cmd->port].block) {
				llist_del(&cmd->entry);
				llist_add_tail(&cmd->entry, &blocked);
				continue;
			}

			mgcp_ss7_do_exec(ss7, cmd->type, cmd->port, cmd->param);
			llist_del(&cmd->entry);
			free(cmd);

			/* We might have unblocked something, make sure we operate in order */
    			MtnSaPoll();
			goto start_over;
		}

		Force_Poll(20);
	}

	return 0;
}
#endif

static void update_mute_status(int mgw_port, int conn_mode)
{
#ifndef NO_UNIPORTE
	if (conn_mode == MGCP_CONN_NONE) {
		MtnSaSetManObject(mgw_port, ChannelType_PORT, ManObj_C_VOICE_UPSTREAM_MUTE, 1, 0);
		MtnSaSetManObject(mgw_port, ChannelType_PORT, ManObj_C_VOICE_DOWNSTREAM_MUTE, 1, 0);
	} else if (conn_mode == MGCP_CONN_RECV_ONLY) {
		MtnSaSetManObject(mgw_port, ChannelType_PORT, ManObj_C_VOICE_UPSTREAM_MUTE, 1, 0);
		MtnSaSetManObject(mgw_port, ChannelType_PORT, ManObj_C_VOICE_DOWNSTREAM_MUTE, 0, 0);
	} else if (conn_mode == MGCP_CONN_SEND_ONLY) {
		MtnSaSetManObject(mgw_port, ChannelType_PORT, ManObj_C_VOICE_UPSTREAM_MUTE, 0, 0);
		MtnSaSetManObject(mgw_port, ChannelType_PORT, ManObj_C_VOICE_DOWNSTREAM_MUTE, 1, 0);
	} else if (conn_mode == MGCP_CONN_RECV_SEND) {
		MtnSaSetManObject(mgw_port, ChannelType_PORT, ManObj_C_VOICE_UPSTREAM_MUTE, 0, 0);
		MtnSaSetManObject(mgw_port, ChannelType_PORT, ManObj_C_VOICE_DOWNSTREAM_MUTE, 0, 0);
	} else {
		LOGP(DMGCP, LOGL_ERROR, "Unhandled conn mode: %d\n", conn_mode);
	}
#endif
}

#ifndef NO_UNIPORTE
static void allocate_endp(struct mgcp_ss7 *ss7, int endp_no)
{
	int mgw_port;
	unsigned long mgw_address, loc_address;
	struct mgcp_ss7_endpoint *mgw_endp = &ss7->mgw_end[endp_no];
	struct mgcp_endpoint *mg_endp = &ss7->cfg->endpoints[endp_no];

	mgw_port = TO_MGW_PORT(endp_no);
	mgw_endp->port = MtnSaAllocate(mgw_port);
	if (mgw_endp->port == UINT_MAX) {
		fprintf(stderr, "Failed to allocate the port: %d\n", endp_no);
		return;
	}

	/* Select AMR 5.9, Payload 98, no CRC, hardcoded */
	MtnSaApplyProfile(mgw_port, ProfileType_VOICE, 0);
	MtnSaSetManObject(mgw_port, ChannelType_PORT,
			  ManObj_G_DATA_PATH, DataPathT_ETHERNET, 0 );
	MtnSaSetManObject(mgw_port, ChannelType_PORT,
			  ManObj_C_VOICE_RTP_TELEPHONE_EVENT_PT_TX, ss7->cfg->audio_payload, 0);
	MtnSaSetManObject(mgw_port, ChannelType_PORT,
			  ManObj_G_RTP_AMR_PAYLOAD_TYPE, ss7->cfg->audio_payload, 0);
	MtnSaSetManObject(mgw_port, ChannelType_PORT,
			  ManObj_G_RTP_AMR_PAYLOAD_FORMAT, RtpAmrPayloadFormat_OCTET_ALIGNED, 0);
	MtnSaSetManObject(mgw_port, ChannelType_PORT,
			  ManObj_G_VOICE_ENCODING, Voice_Encoding_AMR_5_90, 0);
	MtnSaSetManObject(mgw_port, ChannelType_PORT,
			  ManObj_C_VOICE_VAD_CNG, s_vad_enabled, 0);

	update_mute_status(mgw_port, mg_endp->conn_mode);

	/* set the addresses */
	SysEthGetHostAddress(ss7->cfg->bts_ip, &mgw_address);
	SysEthGetHostAddress(ss7->cfg->local_ip, &loc_address);
	MtnSaSetVoIpAddresses(mgw_port,
			      mgw_address, mg_endp->rtp_port,
			      loc_address, mg_endp->rtp_port);
	MtnSaConnect(mgw_port, mgw_port);
	mgw_endp->block = 1;
}
#endif

static void mgcp_ss7_do_exec(struct mgcp_ss7 *mgcp, uint8_t type, uint32_t port, uint32_t param)
{
#ifndef NO_UNIPORTE
	struct mgcp_ss7_endpoint *mgw_endp = &mgcp->mgw_end[port];
	int rc;

	switch (type) {
	case MGCP_SS7_MUTE_STATUS:
		if (mgw_endp->port != UINT_MAX)
			update_mute_status(TO_MGW_PORT(port), param);
		break;
	case MGCP_SS7_DELETE:
		if (mgw_endp->port != UINT_MAX) {
			rc = MtnSaDisconnect(mgw_endp->port);
			if (rc != 0)
				fprintf(stderr, "Failed to disconnect port: %u\n", mgw_endp->port);
			rc = MtnSaDeallocate(mgw_endp->port);
			if (rc != 0)
				fprintf(stderr, "Failed to deallocate port: %u\n", mgw_endp->port);
			mgw_endp->port = UINT_MAX;
			mgw_endp->block = 1;
		}
		break;
	case MGCP_SS7_ALLOCATE:
		allocate_endp(mgcp, port);
		break;
	case MGCP_SS7_SHUTDOWN:
		MtnSaShutdown();
		break;
	}
#endif
}

void mgcp_ss7_exec(struct mgcp_ss7 *mgcp, uint8_t type, uint32_t port, uint32_t param)
{
	struct mgcp_ss7_cmd *cmd = malloc(sizeof(*cmd));
	memset(cmd, 0, sizeof(*cmd));
	cmd->type = type;
	cmd->port = port;
	cmd->param = param;

	thread_safe_add(mgcp->cmd_queue, &cmd->entry);
}

static int ss7_allocate_endpoint(struct mgcp_ss7 *ss7, int endp_no, struct mgcp_ss7_endpoint *endp)
{
	struct mgcp_endpoint *mg_endp;

	mg_endp = &ss7->cfg->endpoints[endp_no];
	mg_endp->bts_rtp = htons(mg_endp->rtp_port);
	mg_endp->bts_rtcp = htons(mg_endp->rtp_port + 1);
	mg_endp->bts = ss7->cfg->bts_in;

	mgcp_ss7_exec(ss7, MGCP_SS7_ALLOCATE, endp_no, 0);
	return MGCP_POLICY_CONT;
}

static int ss7_modify_endpoint(struct mgcp_ss7 *ss7, int endp_no, struct mgcp_ss7_endpoint *endp)
{
 	struct mgcp_endpoint *mg_endp;

 	mg_endp = &ss7->cfg->endpoints[endp_no];
	mgcp_ss7_exec(ss7, MGCP_SS7_MUTE_STATUS, endp_no, mg_endp->conn_mode);

	/*
	 * Just assume that we have the data now.
	 */
	mgcp_send_dummy(mg_endp);

	/* update the remote end */
	return MGCP_POLICY_CONT;
}

static int ss7_delete_endpoint(struct mgcp_ss7 *ss7, int endp_no, struct mgcp_ss7_endpoint *endp)
{
	mgcp_ss7_endp_free(ss7, endp_no);
	return MGCP_POLICY_CONT;
}

static int mgcp_ss7_policy(struct mgcp_config *cfg, int endp_no, int state, const char *trans)
{
	int rc;
	struct mgcp_ss7 *ss7;
	struct mgcp_ss7_endpoint *endp;

	ss7 = (struct mgcp_ss7 *) cfg->data;
	endp = &ss7->mgw_end[endp_no];

	/* TODO: Make it async and wait for the port to be connected */
	rc = MGCP_POLICY_REJECT;
	switch (state) {
	case MGCP_ENDP_CRCX:
		rc = ss7_allocate_endpoint(ss7, endp_no, endp);
		break;
	case MGCP_ENDP_MDCX:
		rc = ss7_modify_endpoint(ss7, endp_no, endp);
		break;
	case MGCP_ENDP_DLCX:
		rc = ss7_delete_endpoint(ss7, endp_no, endp);
		break;
	}
	
	return rc;
}

static void enqueue_msg(struct write_queue *queue, struct sockaddr_in *addr, struct msgb *msg)
{
	struct sockaddr_in *data;

	data = (struct sockaddr_in *) msgb_push(msg, sizeof(*data));
	*data = *addr;
	if (write_queue_enqueue(queue, msg) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to queue the message.\n");
		msgb_free(msg);
	}
}

static int write_call_agent(struct bsc_fd *bfd, struct msgb *msg)
{
	int rc;
	struct sockaddr_in *addr;

	addr = (struct sockaddr_in *) msg->data;
	rc = sendto(bfd->fd, msg->l2h, msgb_l2len(msg), 0,
		    (struct sockaddr *) addr, sizeof(*addr));

	if (rc != msgb_l2len(msg))
		LOGP(DMGCP, LOGL_ERROR, "Failed to write MGCP message: rc: %d errno: %d\n", rc, errno);

	return rc;
}


static int read_call_agent(struct bsc_fd *fd)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct msgb *resp;
	struct mgcp_ss7 *cfg;
	struct write_queue *queue;

	cfg = (struct mgcp_ss7 *) fd->data;
	queue = container_of(fd, struct write_queue, bfd);

	/* read one less so we can use it as a \0 */
	int rc = recvfrom(fd->fd, cfg->mgcp_msg->data, cfg->mgcp_msg->data_len - 1, 0,
		(struct sockaddr *) &addr, &slen);

	if (rc < 0) {
		perror("Gateway failed to read");
		return -1;
	} else if (slen > sizeof(addr)) {
		fprintf(stderr, "Gateway received message from outerspace: %d %d\n",
			slen, sizeof(addr));
		return -1;
	}

	/* handle message now */
	cfg->mgcp_msg->l2h = msgb_put(cfg->mgcp_msg, rc);
	resp = mgcp_handle_message(cfg->cfg, cfg->mgcp_msg);
	msgb_reset(cfg->mgcp_msg);

	if (resp)
		enqueue_msg(queue, &addr, resp);
	return 0;
}

static int create_socket(struct mgcp_ss7 *cfg)
{
	int on;
	struct sockaddr_in addr;
	struct bsc_fd *bfd;

	bfd = &cfg->mgcp_fd.bfd;

	cfg->mgcp_fd.read_cb = read_call_agent;
	cfg->mgcp_fd.write_cb = write_call_agent;
	bfd->when = BSC_FD_READ;
	bfd->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (bfd->fd < 0) {
		perror("Gateway failed to listen");
		return -1;
	}

	on = 1;
	setsockopt(bfd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg->cfg->source_port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(bfd->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Gateway failed to bind");
		close(bfd->fd);
		return -1;
	}

	bfd->data = cfg;
	cfg->mgcp_msg = msgb_alloc(4096, "mgcp-msg");
	if (!cfg->mgcp_msg) {
		fprintf(stderr, "Gateway memory error.\n");
		close(bfd->fd);
		return -1;
	}
	talloc_steal(cfg, cfg->mgcp_msg);


	if (bsc_register_fd(bfd) != 0) {
		DEBUGP(DMGCP, "Failed to register the fd\n");
		close(bfd->fd);
		return -1;
	}

	return 0;
}

static void mgcp_ss7_endp_free(struct mgcp_ss7 *ss7, int endp)
{
	mgcp_ss7_exec(ss7, MGCP_SS7_DELETE, endp, 0);
}

static int reset_cb(struct mgcp_config *cfg)
{
	mgcp_ss7_reset((struct mgcp_ss7 *) cfg->data);
	return 0;
}

static int realloc_cb(struct mgcp_config *cfg, int endp)
{
	mgcp_ss7_endp_free((struct mgcp_ss7 *) cfg->data, endp);
	return 0;
}

static void mgcp_ss7_set_default(struct mgcp_config *cfg)
{
	/* do not attempt to allocate call ids */
	cfg->early_bind = 1;

	talloc_free(cfg->audio_name);
	cfg->audio_payload = 126;
	cfg->audio_name = talloc_strdup(cfg, "AMR/8000");
}

static struct mgcp_ss7 *mgcp_ss7_init(struct mgcp_config *cfg)
{
	int i;
	struct mgcp_ss7 *conf = talloc_zero(NULL, struct mgcp_ss7);
	if (!conf)
		return NULL;

	write_queue_init(&conf->mgcp_fd, 30);
	conf->cfg = cfg;

	/* take over the ownership */
	talloc_steal(conf, conf->cfg);

	conf->cfg->policy_cb = mgcp_ss7_policy;
	conf->cfg->reset_cb = reset_cb;
	conf->cfg->realloc_cb = realloc_cb;
	conf->cfg->data = conf;


	if (mgcp_endpoints_allocate(conf->cfg) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate endpoints: %d\n",
		     cfg->number_endpoints);
		talloc_free(conf);
		return NULL;
	}

	if (create_socket(conf) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create socket.\n");
		talloc_free(conf);
		return NULL;
	}

	conf->mgw_end = _talloc_zero_array(conf, sizeof(struct mgcp_ss7_endpoint),
					   conf->cfg->number_endpoints, "mgw endpoints");
	if (!conf->mgw_end) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate MGW endpoint array.\n");
		talloc_free(conf);
		return NULL;
	}

	for (i = 0; i < conf->cfg->number_endpoints; ++i) {
		struct mgcp_endpoint *endp;
		int rtp_port;

		/* initialize the MGW part */
		conf->mgw_end[i].port = UINT_MAX;

		/* allocate the ports */
		endp = &conf->cfg->endpoints[i];
		rtp_port = rtp_calculate_port(ENDPOINT_NUMBER(endp), conf->cfg->rtp_base_port);
		if (mgcp_bind_rtp_port(endp, rtp_port) != 0) {
			LOGP(DMGCP, LOGL_ERROR, "Failed to bind: %d\n", rtp_port);
			mgcp_ss7_free(conf);
			return NULL;
		}
	}

	conf->cmd_queue = thread_notifier_alloc();
	if (!conf->cmd_queue) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate the command queue.\n");
		talloc_free(conf);
		return NULL;
	}

#ifndef NO_UNIPORTE
	conf->cmd_queue->no_write = 1;
	pthread_create(&conf->thread, NULL, start_uniporte, conf);
#endif

	return conf;
}

void mgcp_ss7_free(struct mgcp_ss7 *mgcp)
{
	/* close everything */
	mgcp_ss7_reset(mgcp);

	mgcp_ss7_exec(mgcp, MGCP_SS7_SHUTDOWN, 0, 0);

	close(mgcp->mgcp_fd.bfd.fd);
	bsc_unregister_fd(&mgcp->mgcp_fd.bfd);
	bsc_del_timer(&mgcp->poll_timer);
	talloc_free(mgcp);
}

void mgcp_ss7_reset(struct mgcp_ss7 *mgcp)
{
	int i;

	if (!mgcp)
		return;

	LOGP(DMGCP, LOGL_INFO, "Resetting all endpoints.\n");

	/* free UniPorted and MGCP data */
	for (i = 0; i < mgcp->cfg->number_endpoints; ++i) {
		mgcp_ss7_endp_free(mgcp, i);
		mgcp_free_endp(&mgcp->cfg->endpoints[i]);
	}
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h This help text.\n");
	printf("  -c --config=CFG. The configuration file.\n");
	printf("  -e --exit-on-failure. Exit the app on MGW failure.\n");
}

static void print_usage()
{
	printf("Usage: mgcp_mgw\n");
}


static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config", 1, 0, 'c'},
			{"exit", 0, 0, 'e'},
			{0, 0, 0, 0},
		}; 

		c = getopt_long(argc, argv, "hc:e",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'c':
			config_file = optarg;
			break;
		case 'e':
			exit_on_failure = 1;
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			break;
		}
	}
}


int main(int argc, char **argv)
{
	struct mgcp_ss7 *mgcp;
	int rc;

	log_init(&log_info);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);

	/* enable filters */
	log_set_all_filter(stderr_target, 1);
	log_set_category_filter(stderr_target, DINP, 1, LOGL_INFO);
	log_set_category_filter(stderr_target, DSCCP, 1, LOGL_INFO);
	log_set_category_filter(stderr_target, DMSC, 1, LOGL_INFO);
	log_set_category_filter(stderr_target, DMGCP, 1, LOGL_INFO);
	log_set_print_timestamp(stderr_target, 1);
	log_set_use_color(stderr_target, 0);

	handle_options(argc, argv);

	signal(SIGPIPE, SIG_IGN);

	mgcp_mgw_vty_init();

	g_cfg = mgcp_config_alloc();
	if (!g_cfg) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate mgcp config.\n");
		return -1;
	}

	mgcp_ss7_set_default(g_cfg);
	mgcp_vty_set_config(g_cfg);
	if (vty_read_config_file(config_file, NULL) < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return -1;
	}

	rc = telnet_init(NULL, NULL, 4243);
	if (rc < 0)
		return rc;

	printf("Creating MGCP MGW with endpoints: %d ip: %s mgw: %s rtp-base: %d payload: %d\n",
		g_cfg->number_endpoints, g_cfg->local_ip, g_cfg->bts_ip,
		g_cfg->rtp_base_port, g_cfg->audio_payload);

	mgcp = mgcp_ss7_init(g_cfg);
	if (!mgcp) {
		fprintf(stderr, "Failed to create MGCP\n");
		exit(-1);
	}
        while (1) {
		bsc_select_main(0);
        }
	return 0;
}

static struct vty_app_info vty_info = {
	.name 		= "mgcp_ss7",
	.version	= "0.0.1",
	.go_parent_cb	= NULL,
};

void logging_vty_add_cmds(void);

DEFUN(cfg_mgcp_vad, cfg_mgcp_vad_cmd,
      "vad (enabled|disabled)",
      "Enable the Voice Activity Detection\n"
      "Enable\n" "Disable\n")
{
	if (argv[0][0] == 'e')
		s_vad_enabled = 1;
	else
		s_vad_enabled = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_realloc, cfg_mgcp_realloc_cmd,
      "force-realloc (0|1)",
      "Force the reallocation of an endpoint\n"
      "Disable\n" "Enable\n")
{
	g_cfg->force_realloc = atoi(argv[0]);
	return CMD_SUCCESS;
}

void mgcp_write_extra(struct vty *vty)
{
	vty_out(vty, "  force-realloc %d%s", g_cfg->force_realloc, VTY_NEWLINE);
	vty_out(vty, "  vad %s%s", s_vad_enabled ? "enabled" : "disabled", VTY_NEWLINE);
}

static void mgcp_mgw_vty_init(void)
{
	cmd_init(1);
	vty_init(&vty_info);
	logging_vty_add_cmds();
	mgcp_vty_init();

	install_element(MGCP_NODE, &cfg_mgcp_vad_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_realloc_cmd);
}


const char *openbsc_copyright = "";
