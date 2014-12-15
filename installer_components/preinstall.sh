#!/bin/bash

# Prefix all paths with $TARGET
if [ "$3" == "/" ]; then
    TARGET=""
else
    TARGET="$3"
fi

# install pymacadmin if not present
if [ ! -f "${TARGET}/usr/local/sbin/crankd.py" ]; then
	cd $(dirname "$0")
	mkdir -p "${TARGET}/usr/local/sbin"
	cp pymacadmin/bin/crankd.py "${TARGET}/usr/local/sbin/"
	mkdir -p "${TARGET}/Library/Application Support/crankd"
	cp -R pymacadmin/lib/PyMacAdmin "${TARGET}/Library/Application Support/crankd/"
fi

exit 0