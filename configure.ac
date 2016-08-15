dnl Process this file with autoconf to produce a configure script
AC_INIT([cellmgr_ng],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc-devel@lists.openbsc.org])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

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
PKG_CHECK_MODULES([LIBOSMOCORE], [libosmocore >= 0.3.2])
PKG_CHECK_MODULES([LIBOSMOGSM], [libosmogsm >= 0.3.2])
PKG_CHECK_MODULES([LIBOSMOSCCP], [libosmo-sccp])
PKG_CHECK_MODULES([LIBOSMOVTY], [libosmovty >= 0.3.2])
#PKG_CHECK_MODULES([NEXUSWARE_C7], [nexusware-c7])

AC_ARG_ENABLE([external_tests],
		AC_HELP_STRING([--enable-external-tests],
				[Include the VTY tests in make check [default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
if test "x$enable_ext_tests" = "xyes" ; then
	AM_PATH_PYTHON
	AC_CHECK_PROG(OSMOTESTEXT_CHECK,osmotestvty.py,yes)
	 if test "x$OSMOTESTEXT_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install osmocom-python to run the VTY tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY tests])
AC_MSG_RESULT([$enable_ext_tests])
AM_CONDITIONAL(ENABLE_EXT_TESTS, test "x$enable_ext_tests" = "xyes")

old_libs=$LIBS
AC_CHECK_LIB([sctp], sctp_sendmsg, [], [AC_MSG_ERROR([The sctp library is required.])])
LIBS=$old_libs

AC_ARG_ENABLE([uniporte], [AS_HELP_STRING([--enable-uniporte], [Build with uniporte])],
   [
       PKG_CHECK_MODULES([NEXUSWARE_UNIPORTE], [nexusware-uniporte])
       AC_SUBST(UNIPORTE, [])
   ],
   [
       AC_SUBST(UNIPORTE, [-DNO_UNIPORTE])
   ])

AM_CONFIG_HEADER(cellmgr_config.h)

AC_OUTPUT(
    include/Makefile
    include/mgcp/Makefile
    src/Makefile
    tests/Makefile
    tests/mtp/Makefile
    tests/patching/Makefile
    tests/isup/Makefile
    tests/mgcp/Makefile
    tests/dtmf/Makefile
    Makefile)
