#!/bin/bash -ex

ROOTDIR=$(git rev-parse --show-toplevel)

cd $ROOTDIR
git clone --depth 1 -b v1.17.0.0_tigermoth_rc1 https://github.com/Linaro/odp.git
cd odp
./bootstrap
ODPDIR=$(pwd)/install
./configure --prefix=$ODPDIR --enable-deprecated
make -j 4 install

cd $ROOTDIR
./bootstrap
./configure --with-odp=$ODPDIR --enable-cunit --prefix=$(pwd)/install
make install
make check
