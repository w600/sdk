**********文件说明**********

secboot.img     w600的second boot文件，类似于bootloader功能
xxxxx.bin       编译生成的原始文件
xxxxx_gz.img    经过gzip压缩后的w600 用户程序，可通过secboot进行串口升级或ota升级
xxxxx.fls       合并了用户程序和secboot的文件，可用于更新secboot或芯片首次烧录
xxxxx.map       bin文件对应的map数据