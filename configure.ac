AC_INIT([libtins], [1.2], [matias.fontanini@gmail.com], [libtins], [http://libtins.sourceforge.net])
AC_CANONICAL_SYSTEM
AC_CONFIG_HEADER(include/config.h)
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-extra-portability foreign])
LT_INIT([disable-static])
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE([enable])

AC_PROG_CXX
AC_LANG(C++)

AC_PROG_LIBTOOL

# Check that libpcap exists

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

# Options

wpa2_msg="WPA2 decryption(which requires openssl) can be disabled using the --disable-wpa2 flag."

AC_ARG_ENABLE(
    c++11, 
    [  --enable-c++11          enable C++11 features], 
    [AX_CXX_COMPILE_STDCXX_11(noext)]
)

AC_ARG_ENABLE(
    dot11, 
    [  --disable-dot11         disable IEEE 802.11 support], 
    [],
    [
        AC_DEFINE([HAVE_DOT11], 1, Have IEEE 802.11 support)
    ]
)

AC_ARG_ENABLE(
    wpa2, 
    [  --disable-wpa2          disable WPA2 decryption features], 
    [],
    [
        AC_CHECK_HEADERS(
            [openssl/evp.h openssl/hmac.h openssl/aes.h], 
            [], 
            [AC_MSG_ERROR([openssl headers are missing! $wpa2_msg ])]
            AC_DEFINE([HAVE_WPA2_DECRYPTION], 0, Have WPA2 decryption library)
        )
        AC_CHECK_LIB(
            crypto, 
            PKCS5_PBKDF2_HMAC_SHA1, 
            [], 
            [AC_MSG_ERROR([openssl library is missing! $wpa2_msg ])]
        )
        AC_DEFINE([HAVE_WPA2_DECRYPTION], 1, Have WPA2 decryption library)
    ]
)

# Substitute options

AC_SUBST(CXXFLAGS)
AC_SUBST(LIBS)
AC_SUBST(LIBTINS_INCLUDE_DIR)
AC_SUBST([LIBTINS_VERSION], [1:2:0])
AC_CONFIG_FILES([Makefile libtins.pc])
AC_OUTPUT
