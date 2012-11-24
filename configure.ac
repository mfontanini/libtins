AC_INIT(myconfig, 0.2)

AC_PROG_CXX()
AC_LANG(C++)

if test -n "$debug"
then
    CFLAGS="-DTINS_DEBUG -g"
else
    CFLAGS="-O3"
fi

AC_ARG_ENABLE(
    c++11, 
    [  --enable-c++11          enable C++11 features], 
    [CFLAGS="$CFLAGS -std=c++0x"]
)



AC_CHECK_HEADERS([pcap.h])
AC_CHECK_LIB(pcap, pcap_loop, [], [AC_MSG_ERROR([pcap library is needed!])])
AC_SUBST(CFLAGS)
AC_OUTPUT(Makefile)
