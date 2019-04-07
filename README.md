`1. 当前 sdk 版本 v3.2.0 ，建议首次升级时先下载 FLS 文件，固件烧录请参考` http://docs.thingsturn.com/application_note/download_firmware/

`2. 重点优化了低功耗模式，目前功耗有明显改善。`

`3. 当前支持 2M flash 版本 W600，单用户区高达960KB。`

# 更新说明

请查看 [ChangeLog](./doc/ChangeLog.txt)
    
# 编译说明

## 1. 使用 Keil 编译

使用 MDK 打开 WM_SDK/tools/Keil/Project/WM_W600.uvproj ，点击 Project -》Build Target 即可编译

需要swd调试的用户请参考 http://docs.thingsturn.com/application_note/swd_debugging/

## 2. 使用 Eclipse 编译

打开 Eclipse 环境，右键项目名称，执行 Build Project 即可。环境搭建请参考  http://docs.thingsturn.com/development/soc/start/

## 3. 使用控制台编译

`使用 Linux 平台编译时，需更新tools/makeimg 和 tools/makeimg_all 的执行权限，如 chmod 755 makeimg `

### 常用指令

make	// 执行编译

make clean	//清理编译过程中的中间文件

make erase	//擦除flash

make flash	//编译并烧录 w600\_gz.img

make flash_all	//编译并烧录 w600.fls 固件

#### 可带参数：

* COMPILE=gcc 

  默认gcc，可选armcc

* TARGET=w600 

  生成的bin文件名称，默认为w600

* DL_PORT=COM6 

  make flash 进行固件烧录时使用的端口号，默认COM1

* DL_BAUD=2000000

  make flash 进行固件烧录时使用的波特率，默认 2Mbps，部分型号的串口不支持。

  支持 2000000, 1000000, 921600, 460800, 115200等不同速率及进行下载.

* FLASH_SIZE=1M 

  编译时指定实际使用的flash大小，默认为1M

#### 示例

* 使用 armcc 进行固件编译

  make COMPILE=armcc 	//使用armcc编译

* 使用 gcc 进行固件编译

  make COMPILE=gcc	 		//使用gcc编译

* 使用 gcc 进行固件编译并烧录，端口 COM8，下载波特率 1Mbps

  make flash COMPILE=gcc DL_PORT=COM8 DL_BAUD=1000000

# Example 编译说明

请查看 [README](./example/README.md)

# 其它

- GCC版本下载：https://launchpad.net/gcc-arm-embedded/4.9/4.9-2014-q4-major/
- 为缩短编译时间，platform 和 src 目录内的源码，不参与每一次的应用层编译，如修改该目录内文件，可运行对应目录下的make_xxx_lib.sh，更新/lib下的文件，下次编译时即可链接更新后的文件.
- 可修改根目录下 Makefile ，USE_LIB=0，则默认使用源码编译。
- 使用 armcc 编译时，需修改 tools/too_chain.def 下面的 Line 38：KEIL_PATH 路径和 Line 45：INC 路径。
- 有任何疑问或问题反馈，可联系 support@thingsturn.com