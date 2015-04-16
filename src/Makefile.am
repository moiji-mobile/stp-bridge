AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
		$(LIBOSMOGSM_CFLAGS) \
		$(NEXUSWARE_C7_CFLAGS) $(NEXUSWARE_UNIPORTE_CFLAGS) $(UNIPORTE)

sbin_PROGRAMS = cellmgr_ng osmo-stp mgcp_mgw

mgcp_mgw_SOURCES = mgcp_ss7.c mgcp_ss7_vty.c mgcp_hw.c thread.c debug.c \
		   mgcp/mgcp_protocol.c mgcp/mgcp_network.c mgcp/mgcp_vty.c \
		   dtmf_scheduler.c
mgcp_mgw_LDADD = $(LAFORGE_LIBS) $(NEXUSWARE_C7_LIBS) $(NEXUSWARE_UNIPORTE_LIBS) \
		 $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS) -lpthread -lcrypto -lrt

cellmgr_ng_SOURCES = main.c mtp_layer3.c thread.c input/ipaccess.c pcap.c \
		     bss_patch.c bssap_sccp.c bsc_sccp.c bsc_ussd.c links.c \
		     msc_conn.c link_udp.c snmp_mtp.c debug.c isup.c \
		     mtp_link.c counter.c sccp_state.c bsc.c ss7_application.c \
		     vty_interface_legacy.c vty_interface_cmds.c mgcp_patch.c \
		     mgcp_callagent.c  isup_filter.c
cellmgr_ng_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
		   $(LIBOSMOSCCP_LIBS) $(NEXUSWARE_C7_LIBS) \
		   -lpthread -lnetsnmp -lcrypto

osmo_stp_SOURCES = main_stp.c mtp_layer3.c thread.c pcap.c link_udp.c snmp_mtp.c \
		   debug.c links.c isup.c sctp_m2ua.c msc_conn.c sccp_state.c \
		   bss_patch.c bssap_sccp.c bsc_sccp.c bsc_ussd.c input/ipaccess.c \
		   mtp_link.c counter.c bsc.c ss7_application.c \
		   vty_interface.c vty_interface_cmds.c mgcp_patch.c \
		   mgcp_callagent.c isup_filter.c sctp_m3ua_client.c \
		   sctp_m3ua_misc.c
osmo_stp_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
		 $(LIBOSMOSCCP_LIBS) $(NEXUSWARE_C7_LIBS) \
		   -lpthread -lnetsnmp -lcrypto -lxua -lsctp
