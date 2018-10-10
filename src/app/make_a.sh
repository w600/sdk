#!/bin/bash

echo "make lib start"
echo ""

make clean
make COMPILE=gcc  APP_DEBUG=0 DEBUG=0
echo "move lib to folder"
cp .output/w600/lib/libapp.a ../../lib/libapp.a
echo "make lib end"