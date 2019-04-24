## W600 adc example

W600 does not have an external adc pin, but we can use internal adc for temperature measurement

Step 0: Compile and Download

``` 
wch@wch-pc /cygdrive/d/Project/sdk/example
$ ./build.sh adc flash COM3

start...

```

Step 1 :  UART0   Printf

```
w600 adc example, compile @Apr 23 2019 15:15:07
task start ... 
tem: 36.3
tem: 34.3
tem: 33.8
tem: 33.9
```


### About

Please visit www.thingsturn.com or contact support@thingsturn.com
