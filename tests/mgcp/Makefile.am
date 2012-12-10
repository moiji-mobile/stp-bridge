INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)
noinst_PROGRAMS = mgcp_patch_test

EXTRA_DIST = mgcp_patch_test.ok

mgcp_patch_test_SOURCES = mgcp_patch_test.c $(top_srcdir)/src/mgcp_patch.c \
			$(top_srcdir)/src/mgcp/mgcp_protocol.c \
			$(top_srcdir)/src/mgcp/mgcp_network.c \
			$(top_srcdir)/src/debug.c
mgcp_patch_test_LDADD = $(LIBOSMOCORE_LIBS) -lrt
