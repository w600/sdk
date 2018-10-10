#!/bin/bash
set -e

echo "make_lib.sh"
echo ""

for dir in app network os; do
    cd $dir
	make clean
	make COMPILE=armcc APP_DEBUG=0 DEBUG=0
	echo "move lib$dir.lib to lib folder"
	cp .output/w600/lib/lib$dir.lib ../../lib/lib$dir.lib
    cd ..
done;