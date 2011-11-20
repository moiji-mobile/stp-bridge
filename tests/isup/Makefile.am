INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)
noinst_PROGRAMS = isup_parse_test

EXTRA_DIST = isup_parse_test.ok

isup_parse_test_SOURCES = isup_parse_test.c $(top_srcdir)/src/isup.c
isup_parse_test_LDADD = $(LIBOSMOCORE_LIBS)
