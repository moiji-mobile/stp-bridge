AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)
noinst_PROGRAMS = dtmf_test

EXTRA_DIST = dtmf_test.ok

dtmf_test_SOURCES = dtmf_test.c $(top_srcdir)/src/dtmf_scheduler.c
dtmf_test_LDADD = $(LIBOSMOCORE_LIBS)
