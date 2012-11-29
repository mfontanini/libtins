AC_INIT(myconfig, 0.1)

AC_PROG_CXX()
AC_LANG(C++)

CFLAGS="-DTINS_DEBUG -g"

AC_ARG_ENABLE(
    c++11, 
    [  --enable-c++11          enable C++11 features], 
    [CFLAGS="$CFLAGS -std=c++0x"]
)

SOURCE_FILES=$(ls ../src/*cpp src/*cpp src/dot11/*cpp | tr '\n' ' ')

AC_CHECK_HEADERS([pcap.h gtest/gtest.h])
AC_CHECK_LIB(pcap, pcap_loop, [], [AC_MSG_ERROR([pcap library is needed!])])
#AC_CHECK_LIB([gtest_main], [main], [], [AC_MSG_ERROR([gtest library is needed!])])
AC_SUBST(CFLAGS)
AC_SUBST(SOURCE_FILES)
AC_OUTPUT(Makefile)
