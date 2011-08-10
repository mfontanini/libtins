AC_INIT(myconfig, 0.1)

AC_PROG_CXX()
AC_LANG(C++)

if test -n "$debug" 
then
    CFLAGS="-DDEBUG -g"
else
    CFLAGS="-O3"
fi

AC_CHECK_HEADERS([])
AC_SUBST(CFLAGS)
AC_OUTPUT(Makefile)
