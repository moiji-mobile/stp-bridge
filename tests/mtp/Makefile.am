AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include $(LIBOSMOCORE_CFLAGS) -Wall
noinst_PROGRAMS = mtp_parse_test

EXTRA_DIST = mtp_parse_test.ok

mtp_parse_test_SOURCES = mtp_parse_test.c $(top_srcdir)/src/sctp_m3ua_misc.c
mtp_parse_test_LDADD = \
	$(LIBOSMOCORE_LIBS)
