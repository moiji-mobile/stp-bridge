INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)
noinst_PROGRAMS = mgcp_patch_test

mgcp_patch_test_SOURCES = mgcp_patch_test.c $(top_srcdir)/src/mgcp_patch.c
mgcp_patch_test_LDADD = $(LIBOSMOCORE_LIBS)
