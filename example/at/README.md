## W600 at example

compile the w600 at firmware.

Step 0: Compile and Download

``` 
wch@wch-pc /cygdrive/d/Project/sdk/example
$ ./build.sh at flash COM3

start...

```

Step 1 :  UART0   Printf

```
Shenzhen ThingsTurn Technology Co., Ltd.
ready

```
Then you can send AT+E and AT+QVER=? like this :

```

+OK

AT+QVER=?
+OK=H1.00.00.0000,G3.02.00@ 11:20:45 Mar 18 2019

```

### About

Please visit www.thingsturn.com or contact support@thingsturn.com
