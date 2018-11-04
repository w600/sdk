# 编译说明

需使用控制台并输入 ./build.sh PRJ\_NAME 指令进行编译

注意：

1. 固件默认生成路径为 sdk/bin/PRJ_NAME/ 文件夹下；
2. 注意 PRJ\_NAME 输入时不要带文件夹后面的"/"，否则编译会出错。

示例：

./build.sh at   //编译at固件，生成的bin文件在 sdk/bin/at/目录下
./build.sh at flash //编译at固件，并烧录，默认串口为 COM1，请自行修改 build.sh 中对应的 DL\_PORT和 DL\_BAUD