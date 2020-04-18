#!/bin/sh

FLASH_SIZE=1M
COMPILE=gcc

echo ""
echo "please input the lib folder name !!!"
echo "example: all common drivers sys app network os "
echo ""
read name

BUILD_ALL=0

if [ -z "$name" ];then
	echo "error input, exit ! "
	exit 1
else
	LIB_NAME=$name
fi


if [ $LIB_NAME == "all" ]; then
		BUILD_ALL=1
elif [ $LIB_NAME == "common" ]; then
		cd ../platform/common
elif [ $LIB_NAME == "drivers" ]; then
		cd ../platform/drivers
elif [ $LIB_NAME == "sys" ]; then
		cd ../platform/sys
elif [ $LIB_NAME == "app" ]; then
		cd ../src/app
elif [ $LIB_NAME == "network" ]; then
		cd ../src/network
elif [ $LIB_NAME == "os" ]; then
		cd ../src/os
else
		echo "error param, you only can input: all common drivers sys app network os!!!"
		exit 1
fi

if [ $COMPILE == "armcc" ]; then
    echo "use armcc"
    LIB_EXT=".lib"
else
    echo "use gcc"
    LIB_EXT=".a"
fi

if [ $BUILD_ALL == 0 ]; then
	make clean && make COMPILE=$COMPILE
	echo "move lib$name$LIB_EXT to lib folder"
	cp .output/w600/lib/lib$LIB_NAME$LIB_EXT ../../lib/lib$LIB_NAME$LIB_EXT
else
	echo "build all lib!!!!"
	# platform folder lib
	cd ../platform
	for dir in common drivers sys; do
		cd $dir
		make clean
		make COMPILE=$COMPILE
		echo "move lib$dir.lib to lib folder"
		cp .output/w600/lib/lib$dir$LIB_EXT ../../lib/lib$dir$LIB_EXT
		cd ..
	done;

	# src folder lib
	cd ../src
	for dir in app network os; do
		cd $dir
		make clean
		make COMPILE=$COMPILE
		echo "move lib$dir.lib to lib folder"
		cp .output/w600/lib/lib$dir$LIB_EXT ../../lib/lib$dir$LIB_EXT
		cd ..
	done;
fi