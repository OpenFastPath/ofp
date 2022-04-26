#!/bin/bash -xe

JOBS=${JOBS:-$(nproc)}

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
git clone https://github.com/OpenDataPlane/odp-dpdk --branch v1.35.0.0_DPDK_19.11 --depth 1 ./odp-dpdk
pushd odp-dpdk
./bootstrap
PKG_CONFIG_PATH=$(pwd)/../dpdk/install/lib/x86_64-linux-gnu/pkgconfig ./configure --prefix=$(pwd)/install
make -j${JOBS} install
popd

# Build OFP
./bootstrap
./configure --with-odp-lib=odp-dpdk --with-odp=$(pwd)/odp-dpdk/install --prefix=$(pwd)/install
make -j${JOBS} install
