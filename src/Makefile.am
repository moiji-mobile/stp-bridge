INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
		$(NEXUSWARE_C7_CFLAGS) $(NEXUSWARE_UNIPORTE_CFLAGS) $(UNIPORTE)

sbin_PROGRAMS = cellmgr_ng mgcp_mgw

mgcp_mgw_SOURCES = mgcp_ss7.c mgcp/mgcp_protocol.c mgcp/mgcp_network.c thread.c
mgcp_mgw_LDADD = $(LAFORGE_LIBS) $(NEXUSWARE_C7_LIBS) $(NEXUSWARE_UNIPORTE_LIBS) \
		 $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS) -lpthread

cellmgr_ng_SOURCES = main.c mtp_layer3.c thread.c input/ipaccess.c pcap.c \
		     bss_patch.c \
		     openbsc_nat/bssap.c openbsc_nat/tlv_parser.c bssap_sccp.c \
		     msc_conn.c link_udp.c snmp_mtp.c
cellmgr_ng_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) $(NEXUSWARE_C7_LIBS) \
		   -lpthread -lnetsnmp -lcrypto
