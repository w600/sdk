					demo演示操作流程


该文档中用到的demo相关的宏定义在wm_demo.h中。演示demo时需要打开该demo对应的宏定义。
demo演示需要在控制台下进行，打开DEMO_CONSOLE，即打开了控制台。
控制台输入的数据会先判断是否是命令字符串。
如果是命令字符串，则启动测试相应的demo；
如果不是命令字符串，测试socket时会作为数据通过socket发送。

1、gpio demo
	控制台输入t-gpio，从打印信息中即可看到gpio读写结果；
	相关demo代码参见wm_gpio_demo.c。

2、gpio 中断demo
	控制台输入t-ioisr，即可测试gpio12的中断，电平变化会进入到中断回调函数中；
	相关demo代码参见wm_gpio_demo.c。

3、flash demo
	控制台输入t-flash，即可测试flash读写；
	相关demo代码参见wm_flash_demo.c。

4、master spi demo
	测试该功能需要用另一模块作为spi从设备。主从spi接口对接好之后，
	控制台输入t-mspi，即可看到测试结果；
	相关demo代码参见wm_master_spi_demo.c。

5、encrypt demo
	控制台输入t-crypt，即可测试加密API；
	当前demo的接口有：AES-128（加解密），RC4（加解密），MD5，HMAC-MD5，SHA1；
	demo使用的原始数据预存在代码中，16字节；
	加解密计算的结果显示在串口终端；
	相关demo代码参见wm_crypt_demo.c

6、联网demo之 一键配置联网
	控制台输入t-oneshot，模块即处于等待一键配置状态，用手机app发送ssid和密码，等待联网成功。
	相关demo代码参见wm_connect_net_demo.c。

7、联网demo之 api接口联网
	控制台输入t-connect("ssid","pwd")，open网络时pwd需要传空字符串("")。模块即进入联网状态。
	相关demo代码参见wm_connect_net_demo.c。

8、联网demo之 wps pbc联网
	控制台输入t-wpspbc,即可开始WPS PBC模式联网；输入命令之后，按下AP的WPS按钮，即可等待联网结果；
	相关demo代码参见wm_wps_demo.c

9、联网demo之 wps pin联网
10、t-wpsgetpin
	要测试WPS PIN模式联网，需要先输入t-wpsgetpin命令获取PIN Code； 该命令会将8位PIN显示在控制台；
	同时将它应用在即将开始的WPS PIN联网方式；
	之后，控制台输入t-wpspin,即可开始WPS PIN模式联网；需要确保2分钟之内将PIN输入到AP配置页面；
	相关demo代码参见wm_wps_demo.c

11、多播广播demo
	控制台输入t-mcast命令，用一键配置或者其他方式联网成功之后，本demo即向ip(224.1.2.1)，Port(5100)
	的多播组发送20包数据，包长为1024字节。
	相关demo代码参见wm_mcast_demo.c。

12、手机升级demo
	控制台输入t-skfwup命令，用一键配置或者其他方式联网成功之后，本demo即自动创建一个TCP服务器监听65533端口，
	通过手机APP(FwUp)可以对模块通过TCP的方式进行升级。
	相关demo代码参见wm_socket_fwup_demo.c。

13、raw接口的socket client 收发数据demo
	用tcp调试助手建立一个socket server，端口1000，启动监听。
	控制台用remoteip命令设置server的ip地址，然后输入t-rawskc命令，用一键配置或者其他方式联网成功之后，
	即自动创建socket client并与server连接，连接成功之后即可用tcp调试助手和控制台互发数据。
	相关demo代码参见wm_raw_socket_client_demo.c。

14、raw接口的socket server 收发数据demo
	控制台输入t-rawsks命令，用一键配置或其他方式联网成功之后，即自动创建socket server，
	监听端口1020。用tcp调试助手连接该server，连接成功之后即可进行数据通信。
	相关demo代码参见wm_raw_socket_server_demo.c。

15、标准接口的socket client 收发数据demo
	演示方式和raw 接口的socket client一样;
	相关demo代码参见wm_socket_client_demo.c。

16、标准接口的socket server 收发数据demo
	演示方式和raw接口的socket server一样;
	相关demo代码参见wm_socket_server_demo.c。

17、多个socket同时创建的demo
	控制台输入t-stdsocks命令，用一键配置或者其他方式联网成功之后，本demo即自动创建一个TCP服务器监听1234端口，
	可用用tcp调试助手连接该Server，最大支持7个Socket连接，连接成功后，可向模块发送数据，模块会打印收到的数据
	到uart0串口。
	相关demo代码参见wm_socket_server_sel_demo.c。

18、创建软ap的demo
	控制台输入t-softap命令，demo程序自动创建一个“soft_ap_demo”，OPEN的AP；
	可以通过手机、笔记本等来连接此AP测试； 
	相关demo代码参见wm_softap_demo.c; 
	
19、http升级demo
	联网成功后，控制台输入t-httpfwup命令，模块即开始从地址（http://RemoteIP:8080/TestWeb/cuckoo.do）
	下载固件进行升级，其中RemoteIP部分可通过设置远程ip地址命令更改。
	相关demo代码参见wm_http_demo.c。

20、http下载demo
	联网成功后，控制台输入t-httpget命令，模块即开始从地址（http://RemoteIP:8080/TestWeb）
	下载信息并打印在控制台，其中RemoteIP部分可通过设置远程ip地址命令更改。
	相关demo代码参见wm_http_demo.c。

21、http上传demo
	联网成功后，控制台输入t-httppost命令，模块即开始向地址（http://RemoteIP:8080/TestWeb/login.do）post数据，
	参数部分为: user=xxxxx，例如t-httppostuser=WinnerMicro，其中RemoteIP部分可通过设置远程ip地址命令更改。
	相关demo代码参见wm_http_demo.c。

22、设置远程ip地址命令
	命令示例:remoteip=192.168.1.111，该命令配合模块做客户端时使用，设置服务器的ip地址；
	相关demo代码参见wm_uart_demo.c。

23、设置控制台波特率命令
	命令示例:baudrate=115200; 后面需要分号作为命令结束符；
	相关demo代码参见wm_uart_demo.c。

24、关闭控制台命令
	通过控制台下达该命令后，控制台将不再使用，重新打开需要复位模块；
	相关demo代码参见wm_uart_demo.c。

25、demo帮助信息命令
	通过控制台下达该命令后，可以打印出demo的相关说明信息；
	相关demo代码参见wm_uart_demo.c。

26、联网demo之 apsta接口联网
	控制台输入t-apsta("ssid","pwd","ssid2")，open网络时pwd需要传空字符串("")。发送指令后模块即进入联网状态。
	ssid2传入空字符串("")则表明建立的软ap使用和ssid一样的网络名称，加密类型和密码不变。
	相关demo代码参见wm_apsta_demo.c。

