AC_INIT([libtins], [0.3], [matias.fontanini@gmail.com], [libtins], [http://libtins.sourceforge.net])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
LT_INIT([disable-static])

AC_PROG_CXX
AC_LANG(C++)

AC_PROG_LIBTOOL

if test -n "$debug"
then
    CXXFLAGS="-DTINS_DEBUG -g"
else
    CXXFLAGS="-O3"
fi

CXXFLAGS="$CXXFLAGS -Iinclude"

AC_ARG_ENABLE(
    c++11, 
    [  --enable-c++11          enable C++11 features], 
    [CXXFLAGS="$CXXFLAGS -std=c++0x"]
)

# Check that libpcap exists

# Get libpcap library and include locations

AC_ARG_WITH([pcap-include-path],
  [AS_HELP_STRING([--with-pcap-include-path],
    [location of the libpcap headers, defaults to /usr/include/pcap])],
  [CXXFLAGS="$CXXFLAGS -I$withval"; CPPFLAGS="-I$withval"])

AC_ARG_WITH([pcap-lib-path],
  [AS_HELP_STRING([--with-pcap-lib-path], [location of the libpcap libraries])],
  [LIBS="$LIBS -L$withval"])

AC_CHECK_LIB(pcap, pcap_loop, [], [AC_MSG_ERROR([pcap library is missing!])])

CPPFLAGS=""

# Headers

LIBTINS_INCLUDE_DIR="include"
AC_CHECK_HEADERS([pcap.h], [], [AC_MSG_ERROR([libpcap headers are missing!])])

# Substitute options

AC_SUBST(CXXFLAGS)
AC_SUBST(LIBS)
AC_SUBST(LIBTINS_INCLUDE_DIR)
AC_SUBST([LIBTINS_VERSION], [0:3:0])
AC_CONFIG_FILES([Makefile libtins.pc])
AC_OUTPUT
