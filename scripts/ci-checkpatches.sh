#!/bin/bash -x

PATCHES=$1
echo "Run checkpatch for ${PATCHES}"
# Generate patches provided with $1.
# In case of force push and range is broken
# validate only the latest commit if it's not merge commit.

if [ "$PATCHES" = "" ]; then
	git format-patch -1 -M HEAD;
	perl ./scripts/checkpatch.pl *.patch;
	exit $?
fi

git show --summary HEAD| grep -q '^Merge:';
if [ $? -ne 0 ]; then
	git format-patch -1 -M HEAD;
	perl ./scripts/checkpatch.pl *.patch;
	exit $?
fi

git format-patch ${PATCHES}
perl ./scripts/checkpatch.pl *.patch;
