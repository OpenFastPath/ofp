#!/bin/bash -xe

JOBS=${JOBS:-$(nproc)}

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd $(readlink -e $(dirname $0))/..

# Configure hugepages
sysctl vm.nr_hugepages=1000
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Build ODP
git clone https://github.com/OpenDataPlane/odp-dpdk --branch v1.35.0.0_DPDK_19.11 --depth 1
pushd odp-dpdk
./bootstrap
./configure --prefix=$(pwd)/install --enable-deprecated --without-tests --without-examples
make -j${JOBS} install
popd

# Build OFP
./bootstrap
./configure --with-odp-lib=odp-dpdk --with-odp=$(pwd)/odp-dpdk/install --prefix=$(pwd)/install --enable-cunit
make -j${JOBS} install

# Test OFP
make check
