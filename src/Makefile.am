INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
		$(NEXUSWARE_C7_CFLAGS) $(NEXUSWARE_UNIPORTE_CFLAGS) $(UNIPORTE)

sbin_PROGRAMS = cellmgr_ng osmo_stp mgcp_mgw

mgcp_mgw_SOURCES = mgcp_ss7.c mgcp_ss7_vty.c thread.c debug.c \
		   mgcp/mgcp_protocol.c mgcp/mgcp_network.c mgcp/mgcp_vty.c
mgcp_mgw_LDADD = $(LAFORGE_LIBS) $(NEXUSWARE_C7_LIBS) $(NEXUSWARE_UNIPORTE_LIBS) \
		 $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS) -lpthread

cellmgr_ng_SOURCES = main.c mtp_layer3.c thread.c input/ipaccess.c pcap.c \
		     bss_patch.c bssap_sccp.c bsc_sccp.c bsc_ussd.c links.c \
		     msc_conn.c link_udp.c snmp_mtp.c debug.c isup.c \
		     mtp_link.c counter.c sccp_state.c bsc.c ss7_application.c \
		     vty_interface_legacy.c vty_interface_cmds.c
cellmgr_ng_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) $(NEXUSWARE_C7_LIBS) \
		   -lpthread -lnetsnmp -lcrypto

osmo_stp_SOURCES = main_stp.c mtp_layer3.c thread.c pcap.c link_udp.c snmp_mtp.c \
		   debug.c links.c isup.c sctp_m2ua.c msc_conn.c sccp_state.c \
		   bss_patch.c bssap_sccp.c bsc_sccp.c bsc_ussd.c input/ipaccess.c \
		   mtp_link.c counter.c bsc.c ss7_application.c \
		   vty_interface.c vty_interface_cmds.c
osmo_stp_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) $(NEXUSWARE_C7_LIBS) \
		   -lpthread -lnetsnmp -lcrypto -lm2ua -lsctp
