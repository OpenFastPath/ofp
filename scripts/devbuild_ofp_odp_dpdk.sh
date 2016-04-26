#!/bin/bash

export ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export REPOS="${REPOS:-${ROOT_DIR}}"

cd ${REPOS}

# Clone check-odp
rm -Rf ./check-odp/
git clone https://git.linaro.org/lng/check-odp.git
pushd check-odp
git checkout 1dd2ba791b298b9e1f8a0e4339c079979db8b587
popd


# Clone odp-dpdk: v1.7.0.0 + multi-queue support
rm -Rf ./odp-dpdk/
git clone https://git.linaro.org/lng/odp-dpdk.git
pushd odp-dpdk
git checkout 8556e01cd7c5e8f9399260c677175a5872b59da8
popd

# Clone/build DPDK
echo '#include "pcap.h"' | cpp -H -o /dev/null 2>&1
if [ "$?" != "0" ]; then
    echo "Error: pcap is not installed. You may need to install libpcap-dev package."
    exit 1
fi

rm -Rf ./dpdk/
odp-dpdk/scripts/devbuild.sh dpdk
if [ "$?" != "0" ]; then
    echo "Instaling dpdk failed" 1>$2
    exit 1
fi

# Build ODP-DPDK
export CONFIGURE_FLAGS="--enable-debug --enable-debug-print --enable-cunit-support --enable-test-vald --enable-shared=yes"
odp-dpdk/scripts/devbuild.sh odp
if [ "$?" != "0" ]; then
    echo "Instaling dpdk failed"
    exit 1
fi

pushd ${ROOT_DIR}/..
./bootstrap
./configure --with-odp=$REPOS/check-odp/new-build --enable-cunit --enable-debug --prefix=$REPOS/check-odp/new-build
make clean
make
make install
popd
