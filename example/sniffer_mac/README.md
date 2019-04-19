## W600 Sniffer

Use a W600 to listen to the wifi packets sent by nearby devices, get the MAC address and RSSI, and even the SSID

Step 0: Compile and Download

``` 
wch@wch-pc /cygdrive/d/Project/sdk/example
$ ./build.sh sniffer_mac flash COM3

start...

```

Step 1 :  UART0   Printf

```
w600 sniffer example, compile @Apr 19 2019 12:51:03

task start ... 

8C:14:B4:60:09:50|FF:FF:FF:FF:FF:FF|01|TYPE:00|SUB:80|RSSI:-64
42:D6:3C:1A:F2:F9|FF:FF:FF:FF:FF:FF|01|TYPE:00|SUB:80|RSSI:-46
2E:B2:1A:EF:98:5B|FF:FF:FF:FF:FF:FF|01|TYPE:00|SUB:80|RSSI:-48
2E:B2:1A:EF:98:5B|28:6D:CD:09:39:C7|01|TYPE:00|SUB:50|RSSI:-48
2E:B2:1A:EF:98:5B|FF:FF:FF:FF:FF:FF|01|TYPE:00|SUB:80|RSSI:-46
2E:B2:1A:EF:98:5B|F0:6E:0B:D3:77:E4|01|TYPE:00|SUB:50|RSSI:-42
2E:B2:1A:EF:98:5B|28:6D:CD:09:39:C7|01|TYPE:00|SUB:B0|RSSI:-44
2E:B2:1A:EF:98:5B|FF:FF:FF:FF:FF:FF|01|TYPE:00|SUB:80|RSSI:-44
2E:B2:1A:EF:98:5B|28:6D:CD:09:39:C7|01|TYPE:00|SUB:10|RSSI:-44
08:11:96:F7:B8:88|2E:B2:1A:EF:98:5B|01|TYPE:00|SUB:D0|RSSI:-52
2E:B2:1A:EF:98:5B|FF:FF:FF:FF:FF:FF|01|TYPE:00|SUB:80|RSSI:-44
F0:6E:0B:D3:77:E4|FF:FF:FF:FF:FF:FF|01|TYPE:00|SUB:40|RSSI:-50
2E:B2:1A:EF:98:5B|F0:6E:0B:D3:77:E4|01|TYPE:00|SUB:50|RSSI:-42
2E:B2:1A:EF:98:5B|FF:FF:FF:FF:FF:FF|01|TYPE:00|SUB:80|RSSI:-48
2E:B2:1A:EF:98:5B|F0:6E:0B:D3:77:E4|01|TYPE:00|SUB:50|RSSI:-42
```


### About

Please visit www.thingsturn.com or contact support@thingsturn.com





