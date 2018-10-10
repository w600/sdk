#!/bin/bash

echo "make lib start"
echo ""

make clean
make COMPILE=armcc  APP_DEBUG=0 DEBUG=0
echo "move lib to folder"
cp .output/w600/lib/libapp.lib ../../lib/libapp.lib
echo "make lib end"