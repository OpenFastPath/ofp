# Enable -fvisibility=hidden if using a gcc that supports it
OLD_CFLAGS="$CFLAGS"
AC_MSG_CHECKING([whether $CC supports -fvisibility=hidden])
VISIBILITY_CFLAGS="-fvisibility=hidden"
CFLAGS="$CFLAGS $VISIBILITY_CFLAGS"
AC_LINK_IFELSE([AC_LANG_PROGRAM()], AC_MSG_RESULT([yes]),
       [VISIBILITY_CFLAGS=""; AC_MSG_RESULT([no])]);

AC_SUBST(VISIBILITY_CFLAGS)
# Restore CFLAGS; VISIBILITY_CFLAGS are added to it where needed.
CFLAGS=$OLD_CFLAGS
