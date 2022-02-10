#!/bin/bash -ex

ROOTDIR=$(git rev-parse --show-toplevel)

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd $ROOTDIR
git clone --depth 1 -b v1.19.0.1 https://github.com/OpenDataPlane/odp.git
cd odp
./bootstrap
ODPDIR=$(pwd)/install
./configure --prefix=$ODPDIR --enable-deprecated
make -j $(nproc) install

cd $ROOTDIR
./bootstrap
./configure --with-odp=$ODPDIR --enable-cunit --prefix=$(pwd)/install
make -j $(nproc) install
make check
