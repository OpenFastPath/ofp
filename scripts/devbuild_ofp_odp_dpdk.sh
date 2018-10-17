#!/bin/bash -xe

JOBS=${JOBS:-16}
TARGET=${TARGET:-"x86_64-native-linuxapp-gcc"}

export ROOT_DIR=$(readlink -e $(dirname $0))
export REPOS="${REPOS:-${ROOT_DIR}/devbuild_ofp_odp_dpdk}"

mkdir ${REPOS}
cd ${REPOS}

echo '#include "pcap.h"' | cpp -H -o /dev/null 2>&1 || \
    echo "Warning: pcap is not installed. You may need to install libpcap-dev"

echo '#include "numa.h"' | cpp -H -o /dev/null 2>&1 || \
    echo "Warning: NUMA library is not installed. You need to install libnuma-dev"

git -c advice.detachedHead=false clone -q --depth=1 --branch=17.11 http://dpdk.org/git/dpdk-stable dpdk
pushd dpdk
git log --oneline --decorate

#Make and edit DPDK configuration
make config T=${TARGET} O=${TARGET}
pushd ${TARGET}
#To use I/O without DPDK supported NIC's enable pcap pmd:
sed -ri 's,(CONFIG_RTE_LIBRTE_PMD_PCAP=).*,\1y,' .config
popd

#Build DPDK
make -j${JOBS} build O=${TARGET} EXTRA_CFLAGS="-fPIC"
make install O=${TARGET} DESTDIR=${TARGET}
popd

# Clone odp-dpdk
git clone -q https://github.com/Linaro/odp-dpdk
pushd odp-dpdk
git checkout v1.19.0.2_DPDK_17.11

export CONFIGURE_FLAGS="--enable-shared=yes --enable-helper-linux"

#Build ODP
./bootstrap
./configure  --enable-debug --enable-debug-print \
	     --with-dpdk-path=`pwd`/../dpdk/${TARGET}/usr/local --prefix=$(pwd)/install
make -j${JOBS} install
popd

cd ${ROOT_DIR}/..
./bootstrap
./configure --with-odp=$REPOS/odp-dpdk/install --enable-cunit --prefix=$REPOS/install
make -j${JOBS} install
