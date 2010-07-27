dnl Process this file with autoconf to produce a configure script
AC_INIT

AM_INIT_AUTOMAKE(cellmgr_ng, 0.0.1)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB

dnl checks for header files
AC_HEADER_STDC

dnl Check for the SNMP header
AC_CHECK_HEADERS([net-snmp/net-snmp-config.h])

dnl Checks for typedefs, structures and compiler characteristics
PKG_CHECK_MODULES([LAFORGE], [liblaf0rge1])
PKG_CHECK_MODULES([SCCP], [libsccp])
#PKG_CHECK_MODULES([NEXUSWARE_C7], [nexusware-c7])
#PKG_CHECK_MODULES([NEXUSWARE_UNIPORTE], [nexusware-uniporte])

AC_OUTPUT(
    include/Makefile
    include/mgcp/Makefile
    include/openbsc_nat/Makefile
    src/Makefile
    tests/Makefile
    tests/mtp/Makefile
    tests/patching/Makefile
    Makefile)
