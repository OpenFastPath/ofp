#!/bin/bash

export ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export REPOS="${REPOS:-${ROOT_DIR}}"

cd ${REPOS}

# Clone check-odp
rm -Rf ./check-odp/
git clone https://git.linaro.org/lng/check-odp.git
pushd check-odp
git checkout 6a957e933443eaa088eaf8565865eebc321e4700
popd


# Clone odp-dpdk: v1.7.0.0 + multi-queue support
rm -Rf ./odp-dpdk/
git clone https://git.linaro.org/lng/odp-dpdk.git
pushd odp-dpdk
git checkout 7068593f600e2b5a23ee1780d5c722c54e966df1
popd

# Clone/build DPDK
echo '#include "pcap.h"' | cpp -H -o /dev/null 2>&1
if [ "$?" != "0" ]; then
    echo "Error: pcap.h is not detected. You may need to install libpcap-dev package."
fi

rm -Rf ./dpdk/
odp-dpdk/scripts/devbuild.sh dpdk
if [ "$?" != "0" ]; then
    echo "Instaling dpdk failed" 1>$2
    exit 1
fi

# Build ODP-DPDK
export CONFIGURE_FLAGS="--enable-shared=yes"
odp-dpdk/scripts/devbuild.sh odp
if [ "$?" != "0" ]; then
    echo "Instaling dpdk failed"
    exit 1
fi

pushd ${ROOT_DIR}/..
./bootstrap
./configure --with-odp=$REPOS/check-odp/new-build --enable-cunit --prefix=$REPOS/check-odp/new-build --with-odp-lib=odp-dpdk
make clean
make
make install
popd
