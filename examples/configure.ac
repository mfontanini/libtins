AC_INIT(myconfig, 0.1)

AC_PROG_CXX()
AC_LANG(C++)

saved_libs="${LIBS}"
LIBS="${LIBS} -ltins"
AC_MSG_CHECKING(libtins)
AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <tins/dns.h>], 
    [Tins::DNS dummy])],
    [echo done],
    [echo error; echo *** libtins is not installed. Aborting... ***; exit 1])
LIBS="${saved_libs}"

AC_CHECK_HEADERS([tins/tins.h], , [echo "*** Error: libtins' headers are absent ***"; exit 1;])

AC_OUTPUT(Makefile)
