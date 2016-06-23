AC_PREREQ([2.69])
AC_INIT([OpenFastPath],
	m4_esyscmd(./scripts/git_hash.sh .),
	[sorin.vultureanu at enea.com],
	[openfastpath],
	[http://www.enea.com])
AM_INIT_AUTOMAKE([1.9 tar-pax subdir-objects])
AC_CONFIG_SRCDIR([include/config.h.in])
AM_CONFIG_HEADER([include/config.h])


AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O

# Use libtool
LT_INIT([])
AC_SUBST([LIBTOOL_DEPS])
AM_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h memory.h stdint.h stdlib.h string.h sys/socket.h unistd.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([fcntl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T

AC_CHECK_SIZEOF([int *])

AX_TLS

##########################################################################
# Set correct platform library version
##########################################################################
LIBOFP_VERSION=0:0:0
AC_SUBST(LIBOFP_VERSION)

##########################################################################
# Set correct pkgconfig version
##########################################################################
PKGCONFIG_VERSION=$(echo $VERSION | awk -F '.git' '{print $1}')
AC_SUBST(PKGCONFIG_VERSION)

##########################################################################
# Check for pthreads availability
##########################################################################

AX_PTHREAD([], [
	       echo "Error! We require pthreads to be available"
	       exit -1
	       ])
LIBS="$PTHREAD_LIBS $LIBS"
AM_CFLAGS="$AM_CFLAGS $PTHREAD_CFLAGS"
AM_LDFLAGS="$AM_LDFLAGS $PTHREAD_LDFLAGS"
CC="$PTHREAD_CC"

AC_SEARCH_LIBS([timer_create],[rt posix4])

##########################################################################
# Default warning setup
##########################################################################
OFP_CFLAGS="$OFP_CFLAGS -W -Wall -Wstrict-prototypes -Wmissing-prototypes"
OFP_CFLAGS="$OFP_CFLAGS -Wmissing-declarations -Wold-style-definition -Wpointer-arith"
OFP_CFLAGS="$OFP_CFLAGS -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral"
OFP_CFLAGS="$OFP_CFLAGS -Wformat-security -Wundef -Wwrite-strings"
## OFP_CFLAGS="$OFP_CFLAGS -Werror"

OFP_CXXFLAGS="-std=c++11 $OFP_CXXFLAGS"
OFP_CXXFLAGS="-fno-strict-aliasing $OFP_CXXFLAGS"
OFP_CXXFLAGS="-W -Wall -Wextra $OFP_CXXFLAGS"
OFP_CXXFLAGS="-Wmissing-declarations  $OFP_CXXFLAGS"

##########################################################################
# Default include setup
##########################################################################
AM_CFLAGS="$AM_CFLAGS $OFP_CFLAGS"
AM_CXXFLAGS="$AM_CXXFLAGS $OFP_CXXFLAGS"

##########################################################################
# Checks for library functions.
##########################################################################
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa malloc memset socket strerror strrchr])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	example/Makefile
	example/fpm/Makefile
	example/fpm_burstmode/Makefile
	example/socket/Makefile
	example/classifier/Makefile
	example/webserver/Makefile
	example/webserver2/Makefile
	example/udpecho/Makefile
	example/ioctl_test/Makefile
	example/sysctl/Makefile
	example/multicast/Makefile
	example/udp_fwd_socket/Makefile
	example/ofp_netwrap_proc/Makefile
	example/ofp_netwrap_crt/Makefile
	pkgconfig/libofp.pc
	scripts/Makefile
	test/Makefile
	test/cunit/Makefile
	])

AC_ARG_ENABLE([lto],
[AS_HELP_STRING([--enable-lto],[enable link-time optimization @<:@no@:>@])],
[want_lto="${enableval}"], [want_lto=no])
## FIXME: add a test for gcc >= 4.5.0
if test "x${want_lto}" == xyes; then
  AM_CFLAGS="$AM_CFLAGS -flto"
fi

##########################################################################
# adding the ODP library (e.g. with static name 'libodp-linux.a')
##########################################################################

# introduce the optional configure parameter for a non-standard install prefix of XXX
AC_ARG_WITH([odp],
    [AS_HELP_STRING([--with-odp=prefix],
	[non-standard install prefix of odp])],
    [# extend the compiler and linker flags according to the path set
     AM_CPPFLAGS="$AM_CPPFLAGS -I$with_odp/include"
     AM_LDFLAGS="$AM_LDFLAGS -L$with_odp/lib"
     export PKG_CONFIG_PATH=$with_odp/lib/pkgconfig],
    [])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LDFLAGS=$LDFLAGS
OLD_CPPFLAGS=$CPPFLAGS
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
CPPFLAGS="$AM_CPPFLAGS $CPPFLAGS"

ODP_VERSION_SUPPORTED="1.10.0.0"
function check_odp {
	 AC_CHECK_LIB(odp-linux, odp_packet_alloc, [],
	     [AC_MSG_FAILURE(["This package needs OpenDataPlane (libodp.a) installed"])])
	 AC_CHECK_HEADERS([odp.h], [],
	     [AC_MSG_FAILURE(["Can't find ODP headers"])])
	 AC_MSG_FAILURE(["Invalid ODP version. ODP $ODP_VERSION_SUPPORTED is required."])
}

PKG_CHECK_MODULES([ODP], [libodp-linux >= $ODP_VERSION_SUPPORTED], [],
	check_odp)

# prepending lib to the files to link
LIBS="-lodp-linux -lodphelper-linux $LIBS -ldl"

##########################################################################
# Restore old saved variables
##########################################################################
LDFLAGS=$OLD_LDFLAGS
CPPFLAGS=$OLD_CPPFLAGS

# Enable/disable OFP_DEBUG
ofp_debug=no
AC_ARG_ENABLE([debug],
    [  --enable-debug         Enable OFP debug],
    [ofp_debug=$enableval])
if test "$ofp_debug" == "yes" ; then
    AM_CFLAGS="$AM_CFLAGS -DOFP_DEBUG"
fi

# Enable/disable INET6 domain
AC_ARG_ENABLE([ipv6],
    [  --enable-ipv6    Turn on IPv6 processing],
    [case "${enableval}" in
        yes) ipv6_support=true ;;
        no)  ipv6_support=false ;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-ipv6]) ;;
    esac],[ipv6_support=true])
AM_CONDITIONAL([OFP_IPv6], [test x$ipv6_support = xtrue])

# Enable/disable Slow Path processing
AC_ARG_ENABLE([sp],
    [  --enable-sp    Turn on Slow Path processing],
    [case "${enableval}" in
        yes) sp_support=true ;;
        no)  sp_support=false ;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-sp]) ;;
    esac],[sp_support=true])
AM_CONDITIONAL([OFP_SP], [test x$sp_support = xtrue])

# Enable/disable libCK use
AC_ARG_ENABLE([libck],
    [  --enable-libck         Enable/disable use of libCK],
    [case "${enableval}" in
        yes) use_ck=true ;;
        no)  use_ck=false ;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-libck]) ;;
    esac],[use_ck=false])
AM_CONDITIONAL([OFP_USE_LIBCK], [test x$use_ck = xtrue])

# Enable/disable MTRIE IPv4 use
AC_ARG_ENABLE([mtrie],
    [  --enable-mtrie         Enable/disable use of mtrie route tables],
    [case "${enableval}" in
        yes) use_mtrie=true ;;
        no)  use_mtrie=false ;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-mtrie]) ;;
    esac],[use_mtrie=true])
AM_CONDITIONAL([OFP_MTRIE], [test x$use_mtrie = xtrue])


##########################################################################
# Enable/disable Unit tests
##########################################################################
AC_ARG_ENABLE(
	[cunit],
	[  --enable-cunit         Enable/disable cunit],
	[if test x$enableval = xyes; then
		cunit_support=yes
	fi])

AC_ARG_WITH(
	[cunit-path],
	AC_HELP_STRING(
		[--with-cunit-path=DIR Path to Cunit libs and headers],
		[(or in the default path if not specified).]),
	[cunit_support=yes
	 have_cunit_path=yes
	 CUNIT_PATH=$withval],
	[AS_IF(
		[test x$cunit_support = xyes ],
		[AC_CHECK_HEADERS(
			[CUnit/Basic.h], [],
			[AC_MSG_FAILURE(["can't find cunit headers"])])
		])
	])

AC_SUBST(CUNIT_PATH)
AM_CONDITIONAL([HAVE_CUNIT_PATH], [test x$have_cunit_path = xyes])

AM_CONDITIONAL([OFP_CUNIT_ENABLED], [test x$cunit_support = xyes ])

##########################################################################
# adding the quagga dir
##########################################################################

# introduce the optional configure parameter for a non-standard install prefix of XXX
AC_ARG_WITH([quagga],
    [AS_HELP_STRING([--with-quagga=prefix],
	[non-standard path prefix of the quagga source directory])],
    [QUAGGAPATHSET=1],
    [QUAGGAPATHSET=0])

# if optional parameter used, extend path flags for compliler and linker
if test $QUAGGAPATHSET = 1 ; then
    # extend the compiler and linker flags according to the path set
    AM_CPPFLAGS="$AM_CPPFLAGS -I$with_quagga"
    AC_DEFINE(HAVE_QUAGGA, [1], [Have quagga source dir ?])
else
AC_CHECK_HEADERS([fpm/fpm.h], [
		AC_DEFINE(HAVE_QUAGGA, [1], [Have quagga source dir ?])], [])
fi


##########################################################################
# Libconcurrenykit
##########################################################################

# introduce the optional configure parameter for a non-standard install prefix of XXX
AC_ARG_WITH([libck],
    [AS_HELP_STRING([--with-libck=prefix],
	[non-standard path prefix of the concurrenykit install directory])],
    [CKPATHSET=1],
    [CKPATHSET=0])

if test x$use_ck = xtrue ; then
   # if optional parameter used, extend path flags for compliler and linker
   if test $CKPATHSET = 1 ; then
      # extend the compiler and linker flags according to the path set
      AM_CPPFLAGS="$AM_CPPFLAGS -I$with_libck/include"
      AM_LDFLAGS="$AM_LDFLAGS -L$with_libck/lib -L$with_libck/src"
      LIBS="-lck $LIBS"
      AC_DEFINE(HAVE_LIBCK, [1], [Have libconcurrencykit])
   else
      AC_CHECK_HEADERS([ck_epoch.h], [
         AC_DEFINE(HAVE_LIBCK, [1], [Have concurrentykit])], [])

      AC_SEARCH_LIBS([ck_epoch_init],[ck],[], [
         AC_MSG_ERROR([Unable to find libck library])])
   fi
fi

##########################################################################
# adding the RumpKernel dir
##########################################################################

# introduce the optional configure parameter for a non-standard install prefix of XXX
AC_ARG_WITH([buildrump],
    [AS_HELP_STRING([--with-buildrump=prefix],
	[non-standard path prefix of the rump source directory])],
    [RUMPPATHSET=1],
    [RUMPPATHSET=0])

# if optional parameter used, extend path flags for compliler and linker
if test $RUMPPATHSET = 1 ; then
    # extend the compiler and linker flags according to the path set
    AM_CPPFLAGS="$AM_CPPFLAGS -I$with_buildrump/rump/include"
    AM_LDFLAGS="$AM_LDFLAGS -L$with_buildrump/rump/lib/"
    AC_DEFINE(HAVE_BUILDRUMP, [1], [Have buildrump libs ?])
    LIBS="-lrumpclient -lrumpnet_shmif -lrumpnet_config -lrumpnet_netinet6 -lrumpnet_net -lrumpnet -lrump -lrumpuser $LIBS"
else
    AC_CHECK_HEADERS([rump/rump.h], [
		    AC_DEFINE(HAVE_BUILDRUMP, [1], [Have buildrump libs ?])],
		    [])
    AC_SEARCH_LIBS([rumpclient_init],[rumpclient])
    AC_SEARCH_LIBS([rump_pub_shmif_create],[rumpnet_shmif])
    AC_SEARCH_LIBS([rumpns_if_init],[rumpnet_config])
    AC_SEARCH_LIBS([_init],[rumpnet_netinet6])
    AC_SEARCH_LIBS([_init],[rumpnet_netinet])
    AC_SEARCH_LIBS([rumpns_rt_init],[rumpnet_net])
    AC_SEARCH_LIBS([rumpns_rt_inithead],[rumpnet])
    AC_SEARCH_LIBS([rump_init],[rump])
    AC_SEARCH_LIBS([rumpuser_init],[rumpuser])
fi

##########################################################################
# distribute the changed variables among the Makefiles
AC_SUBST([LIBS])
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE $VERSION
	========

	Library version:	${LIBOFP_VERSION}

	prefix:			${prefix}
	sysconfdir:		${sysconfdir}
	libdir:			${libdir}
	includedir:		${includedir}

	cc:                     ${CC}
        cppflags:               ${CPPFLAGS}
        am_cppflags:            ${AM_CPPFLAGS}
	cflags:			${CFLAGS}
	am_cflags:		${AM_CFLAGS}
        am_cxxflags:            ${AM_CXXFLAGS}
	ldflags:		${LDFLAGS}
	am_ldflags:		${AM_LDFLAGS}
	odp_version:		$(pkg-config --modversion libodp-linux)
	cunit:			${cunit_support}
])
