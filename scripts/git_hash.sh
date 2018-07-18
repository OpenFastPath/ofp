#!/bin/bash

if [ -z ${1} ]; then
	echo "should be called with a path"
	exit
fi
ROOTDIR=${1}
GIT_DIR=${1}/.git
SCM_FILE=${1}/.scmversion

if [ -d ${GIT_DIR} ]; then
	export GIT_DIR
	hash=$(git describe --dirty 2>/dev/null | tr -d "\n")
	if [[ "$hash" = "" || "$hash" =~ ^v2\.0_rc1.* ]]; then
		branch=$(git rev-parse --abbrev-ref HEAD)
		hash=$(git rev-parse --short HEAD)
		rm -f ${SCM_FILE}
		[ -n "$branch" ] && echo -n "${branch}." > ${SCM_FILE}
		echo -n "${hash}" >> ${SCM_FILE}
	else
		echo -n "${hash}" > ${SCM_FILE}

		sed -i "s|-|.git|" ${SCM_FILE}
		sed -i "s|-|.|g" ${SCM_FILE}
		sed -i "s|^v||g" ${SCM_FILE}
	fi
elif [ ! -f ${SCM_FILE} ]; then
	echo -n "File ${SCM_FILE} not found, "
	echo "and not inside a git repository"
	echo "Bailing out! Not recoverable!"
	exit 1
fi

cat ${SCM_FILE}
