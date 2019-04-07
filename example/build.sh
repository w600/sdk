#!/bin/sh

DL_PORT=COM1
DL_BAUD=2000000
COMPILE=gcc
FLASH_SIZE=1M

#./build_app_new.sh test_prj debug

if [ -z "$1" ];then
        echo "please input the project folder name !!!"
        exit 1
else
        APP_BIN_NAME=$1
fi

echo ""
echo "start..."
echo ""
if [ -z "$2" ];then
		set -e
		make -f Makefile.mk clean APP_BIN_NAME=$APP_BIN_NAME;
		make -f Makefile.mk COMPILE=$COMPILE APP_BIN_NAME=$APP_BIN_NAME TARGET=$APP_BIN_NAME FLASH_SIZE=$FLASH_SIZE
        exit 1
else
		if [ $2 == "clean" ]; then
			set -e
			make  -f Makefile.mk  clean APP_BIN_NAME=$APP_BIN_NAME;
		elif [ $2 == "flash" ]; then
			if [ -z "$3" ];then
				set -e
				make -f Makefile.mk clean APP_BIN_NAME=$APP_BIN_NAME;
				make -f Makefile.mk flash COMPILE=$COMPILE \
					APP_BIN_NAME=$APP_BIN_NAME TARGET=$APP_BIN_NAME\
					DL_PORT=$DL_PORT DL_BAUD=$DL_BAUD FLASH_SIZE=$FLASH_SIZE
			else
				echo "download..."
				set -e
				make -f Makefile.mk clean APP_BIN_NAME=$APP_BIN_NAME;
				make -f Makefile.mk flash COMPILE=$COMPILE \
					APP_BIN_NAME=$APP_BIN_NAME TARGET=$APP_BIN_NAME\
					DL_PORT=$3 DL_BAUD=$DL_BAUD FLASH_SIZE=$FLASH_SIZE
			fi
		else
			echo "error app param, you can input clean or flash !!!"
			exit 1
		fi
fi

