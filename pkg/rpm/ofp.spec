# Copyright (c) 2016, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

Name: openfastpath
Version: 1.0
Release: 1
Packager: anders.roxell@linaro.org
URL: http://openfastpath.org
Source: %{name}-%{version}.tar.gz
Summary: OpenFastPath implementation
Group: System Environment/Libraries
License: BSD-3-Clause
BuildRequires: automake
BuildRequires: autoconf
BuildRequires: libtool
BuildRequires: odp
BuildRequires: doxygen
%if 0%{?fedora}
BuildRequires: texlive-collection-fontsextra
BuildRequires: texlive-collection-latexextra
%else
BuildRequires: texlive-latex-bin-bin
BuildRequires: texlive-makeindex-bin
BuildRequires: texlive-dvips-bin
%endif

%description
OFP's implementation includes header files and a library
More libraries are available as extensions in other packages.

%package devel
Summary: OpenFastPath implementation
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
OFP devel is a set of headers, a library and example files.
This is a reference implementation.

%package doc
Summary: OpenFastPath documentation
BuildArch: noarch

%description doc
OFP doc is divided in two parts: API details in doxygen HTML format
and guides in HTML formats.

%prep
%autosetup -n %{name}-%{version}

%configure
%make_install

%files
%{_datadir}/*
%{_bindir}/*
%{_libdir}/*

%files devel
%{_includedir}/*
%{_libdir}/

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig
%changelog
* Mon Feb 22 2016 - anders.roxell (at) linaro.org
- Initial rpm release, OFP release v1.0
