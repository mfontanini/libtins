AC_INIT([libtins], [1.0], [matias.fontanini@gmail.com], [libtins], [http://libtins.sourceforge.net])
AC_CANONICAL_SYSTEM
AC_CONFIG_HEADER(include/config.h)
AM_INIT_AUTOMAKE([-Wall -Werror])
LT_INIT([disable-static])
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE([enable])

AC_PROG_CXX
AC_LANG(C++)

AC_PROG_LIBTOOL

CXXFLAGS="$CXXFLAGS -Iinclude"

AC_ARG_ENABLE(
    c++11, 
    [  --enable-c++11          enable C++11 features], 
    [AX_CXX_COMPILE_STDCXX_11(noext)]
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

old_cppflags=$CPPFLAGS
CPPFLAGS=""

# Headers

LIBTINS_INCLUDE_DIR="include"
AC_CHECK_HEADERS([pcap.h], [], [AC_MSG_ERROR([libpcap headers are missing!])])

CPPFLAGS=$old_cppflags

# Substitute options

AC_SUBST(CXXFLAGS)
AC_SUBST(LIBS)
AC_SUBST(LIBTINS_INCLUDE_DIR)
AC_SUBST([LIBTINS_VERSION], [1:0:0])
AC_CONFIG_FILES([Makefile libtins.pc])
AC_OUTPUT
