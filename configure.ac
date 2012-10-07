AC_INIT(myconfig, 0.2)

AC_PROG_CXX()
AC_LANG(C++)

if test -n "$debug"
then
    CFLAGS="-DDEBUG -g"
else
    CFLAGS="-O3"
fi

AC_CHECK_HEADERS([pcap.h])
AC_CHECK_LIB(pcap, pcap_loop, [], [AC_MSG_ERROR([pcap library is needed!])])
AC_SUBST(CFLAGS)
AC_OUTPUT(Makefile)
