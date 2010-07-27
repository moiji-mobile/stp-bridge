INCLUDES = $(all_includes) -I$(top_srcdir)/include $(LAFORGE_CFLAGS) -Wall
noinst_PROGRAMS = patching_test

patching_test_SOURCES = patching_test.c $(top_srcdir)/src/bss_patch.c \
                        $(top_srcdir)/src/openbsc_nat/tlv_parser.c \
                        $(top_srcdir)/src/openbsc_nat/bssap.c
patching_test_LDADD = $(LAFORGE_LIBS) $(SCCP_LIBS)

