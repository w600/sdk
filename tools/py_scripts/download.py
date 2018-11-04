# -*- coding:utf-8 -*-
#
# W600 flash download script
# Copyright (c) 2018 Winner Micro Electronic Design Co., Ltd.
# All rights reserved.
#

import serial
import struct
import platform
import pyprind
import os
import sys
import time
from xmodem import XMODEM1k


class WMDownload(object):

    if platform.system() == 'Windows':
        DEFAULT_PORT = "COM1"
    else:
        DEFAULT_PORT = "/dev/ttyUSB0"
    DEFAULT_BAUD = 115200
    DEFAULT_TIMEOUT = 0.3
    DEFAULT_IMAGE = "../Bin/WM_W600_GZ.img"

    def __init__(self, port=DEFAULT_PORT, baud=DEFAULT_BAUD, timeout=DEFAULT_TIMEOUT, image=DEFAULT_IMAGE):
        self.image = image
        self.ser = serial.Serial(port, baud, timeout=timeout)
        statinfo_bin = os.stat(image)
        self.bar_user = pyprind.ProgBar(statinfo_bin.st_size/1024+2)

    def image_path(self):
        return self.image

    def set_port_baudrate(self, baud):
        self.ser.baudrate = baud
    
    def set_timeout(self, timeout):
        self.ser.timeout  = timeout

    def getc(self, size, timeout=1):
        return self.ser.read(size) or None

    def putc(self, data, timeout=1):
        return self.ser.write(data)

    def putc_bar(self, data, timeout=1):
        self.bar_user.update()
        return self.ser.write(data)

    def open(self):
        self.ser.open()
    
    def close(self):
        self.ser.flush()
        self.ser.flushInput()
        self.ser.close()
    
    def info(self):
        return (self.ser.port , self.ser.baudrate)

def help():
    print('USAGE:')
    print('win:python download.py [COM] [image]')
    print('    COM default：\"COM1\" image default：\"../Bin/WM_W600_GZ.img\"')
    print('    eg：python download.py COM5 ../Bin/WM_W600_GZ.img')
    print('Linux:python3 download.py [COM] [image]')
    print('    COM default：\"ttyUSB0\" image default：\"../Bin/WM_W600_GZ.img\"')
    print('    eg：python3 download.py ttyUSB0 ../Bin/WM_W600_GZ.img')

def main(argv):
    argc = len(argv)
    if argc == 1:
        download = WMDownload()
    elif argc == 2:
        if argv[1] == '--help':
            help()
            return
        else:
            if platform.system() == 'Windows':
                user_port = argv[1]
            else:
                user_port = "/dev/" + argv[1]
            download = WMDownload(port=user_port)
    elif argc == 3:
        if platform.system() == 'Windows':
            user_port = argv[1]
        else:
            user_port = "/dev/" + argv[1]
        download = WMDownload(port=user_port, image=argv[2])
    else:
        help()
        return
    
    print('')
    print("serial open success！com: %s, baudrate: %s;" % download.info())
    print('please restart device!')
    download.set_timeout(0.1)
    while True:
        c = download.getc(1)
        if c == b'C':
            download.putc(bytes.fromhex('210a00ef2a3100000080841e00'))
            break
        else:
            download.putc(struct.pack('<B', 27))
    download.close()
    time.sleep(0.2)
    download.set_port_baudrate(2000000)
    download.open()
    time.sleep(0.2)

    # check baudrate
    while True:
        c = download.getc(1)
        if c == b'C':
            print('serial into high speed mode')
            break
        else:
            download.close()
            download.set_port_baudrate(115200)
            download.open()
            time.sleep(0.2)
            download.putc(bytes.fromhex('210a00ef2a3100000080841e00'))
            download.close()
            download.set_port_baudrate(2000000)
            download.open()
            time.sleep(0.2)

    print("start download %s "  % download.image_path())
    try:
        stream = open(download.image_path(), 'rb+')
    except IOError:
        print("can't open %s file." % download.image_path())
        download.close()
        raise
    else:
        download.set_timeout(1)
        time.sleep(0.2)
        modem = XMODEM1k(download.getc, download.putc_bar)
        print("please wait for download....")
        result = modem.send(stream)
        time.sleep(1)
        print('')
        if result:
            print("download %s image success!" % download.image_path())
        else:
            print("download %s image fail!" % download.image_path())
        download.close()

if __name__ == '__main__':
    main(sys.argv)
