#!/bin/bash
set -e

echo "make_lib.sh"
echo ""

for dir in app network os; do
    cd $dir
	make clean
	make COMPILE=gcc APP_DEBUG=0 DEBUG=0
	echo "move lib$dir.a to lib folder"
	cp .output/w600/lib/lib$dir.a ../../lib/lib$dir.a
    cd ..
done;