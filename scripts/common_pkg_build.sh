#!/bin/bash

set -e

prepare_tarball() {
	export package=openfastpath

	pushd ${ROOT_DIR}

	if [[ -d ${ROOT_DIR}/.git ]]; then
		. scripts/git_hash.sh ${ROOT_DIR}
		version=$(cat ${ROOT_DIR}/.scmversion)
	else
		echo "This script isn't expected to be used without"
		echo "a git repository."
		exit 1
	fi

	if [ "$1" == archive ]; then
		git archive --format=tar --prefix=${package}-${version}/ HEAD > ${package}-${version}.tar

		# append .scmversion, otherwise bootstrap fails
		SCMTMP=`mktemp -d`
		pushd $SCMTMP
		mkdir ${package}-${version}
		cp ${ROOT_DIR}/.scmversion ${package}-${version}
		tar --update -v -f ${ROOT_DIR}/${package}-${version}.tar ${package}-${version}
		popd
		rm -rf $SCMTMP
		gzip ${package}-${version}.tar
	else
		./bootstrap
		./configure
		make dist
	fi

	cp ${package}-${version}.tar.gz ${package}_${version}.orig.tar.gz
	tar xzf ${package}_${version}.orig.tar.gz
}
