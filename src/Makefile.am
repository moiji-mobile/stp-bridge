INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
		$(NEXUSWARE_C7_CFLAGS) $(NEXUSWARE_UNIPORTE_CFLAGS) $(UNIPORTE)

sbin_PROGRAMS = cellmgr_ng udt_relay osmo_stp mgcp_mgw

mgcp_mgw_SOURCES = mgcp_ss7.c thread.c debug.c \
		   mgcp/mgcp_protocol.c mgcp/mgcp_network.c mgcp/mgcp_vty.c
mgcp_mgw_LDADD = $(LAFORGE_LIBS) $(NEXUSWARE_C7_LIBS) $(NEXUSWARE_UNIPORTE_LIBS) \
		 $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS) -lpthread

cellmgr_ng_SOURCES = main.c mtp_layer3.c thread.c input/ipaccess.c pcap.c \
		     bss_patch.c bssap_sccp.c bsc_sccp.c bsc_ussd.c links.c \
		     msc_conn.c link_udp.c snmp_mtp.c debug.c vty_interface.c isup.c \
		     mtp_link.c counter.c
cellmgr_ng_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) $(NEXUSWARE_C7_LIBS) \
		   -lpthread -lnetsnmp -lcrypto

udt_relay_SOURCES = main_udt.c mtp_layer3.c thread.c input/ipaccess.c pcap.c \
		     msc_conn.c link_udp.c snmp_mtp.c debug.c vty_interface.c \
		     bss_patch.c isup.c links.c sctp_m2ua.c mtp_link.c counter.c
udt_relay_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) $(NEXUSWARE_C7_LIBS) \
		   -lpthread -lnetsnmp -lcrypto -lm2ua -lsctp

osmo_stp_SOURCES = main_stp.c mtp_layer3.c thread.c pcap.c link_udp.c snmp_mtp.c \
		   debug.c vty_interface.c links.c isup.c sctp_m2ua.c \
		   mtp_link.c counter.c
osmo_stp_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) $(NEXUSWARE_C7_LIBS) \
		   -lpthread -lnetsnmp -lcrypto -lm2ua -lsctp
