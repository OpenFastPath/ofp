#!/bin/bash -xe

JOBS=${JOBS:-$(nproc)}

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd $(readlink -e $(dirname $0))/..

# Build ODP
git clone https://github.com/OpenDataPlane/odp --branch v1.45.1.0 --depth 1
pushd odp
./bootstrap
./configure --prefix=$(pwd)/install --without-tests --without-examples
make -j${JOBS} install
popd

# Build OFP
./bootstrap
./configure --with-odp=$(pwd)/odp/install --prefix=$(pwd)/install --enable-cunit
make -j${JOBS} install

# Test OFP
make check
