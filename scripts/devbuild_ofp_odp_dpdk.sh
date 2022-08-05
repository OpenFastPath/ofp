#!/bin/bash -xe

JOBS=${JOBS:-$(nproc)}

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd $(readlink -e $(dirname $0))/..

# Build DPDK
git clone http://dpdk.org/git/dpdk-stable --branch 20.11 --depth 1 ./dpdk
pushd dpdk
meson build
pushd build
meson configure -Dprefix=$(pwd)/../install
ninja install
popd
popd

# Build ODP
git clone https://github.com/OpenDataPlane/odp-dpdk --branch v1.35.0.0_DPDK_19.11 --depth 1
pushd odp-dpdk
./bootstrap
PKG_CONFIG_PATH=$(pwd)/../dpdk/install/lib64/pkgconfig:${PKG_CONFIG_PATH} ./configure --prefix=$(pwd)/install
make -j${JOBS} install
popd

# Build OFP
./bootstrap
./configure --with-odp-lib=odp-dpdk --with-odp=$(pwd)/odp-dpdk/install --prefix=$(pwd)/install --enable-cunit
make -j${JOBS} install
