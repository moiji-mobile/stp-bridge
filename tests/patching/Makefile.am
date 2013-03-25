INCLUDES = $(all_includes) -I$(top_srcdir)/include $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) -Wall
noinst_PROGRAMS = patching_test

EXTRA_DIST = patching_test.ok

patching_test_SOURCES = patching_test.c $(top_srcdir)/src/bss_patch.c \
			$(top_srcdir)/src/debug.c
patching_test_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOSCCP_LIBS) $(LIBOSMOGSM_LIBS)

