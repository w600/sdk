# W600 Example 

## Basic Example

* [at](at) : just compile the sdk, do nothing;
* [adc](adc) : use internal adc for temperature measurement;
* [blink](blink) : blink led using a task and os timer delay;
* [blink_timer](blink_timer) : blink led using a hardware timer;
* [flash](flash) : read flash and write flash test.
* [hello world](helloworld): printf helloworld using a task and os timer delay;
* [pwm](pwm) : breathing led using a hardware pwm;

## Advance Example

* [beacon_spam](beacon_spam) : create multiple custom WiFi access points;
* [sniffer_mac](sniffer_mac) : get the MAC address and RSSI, and even the SSID which sent by nearby devices;

 
## Compile

Open the Cygwin console and enter the ./build.sh PRJ\_NAME cmd

``` 
wch@wch-pc /cygdrive/d/Project/sdk/example
$ ./build.sh at

start...
```
Or download directly to the w600 device

``` 
wch@wch-pc /cygdrive/d/Project/sdk/example
$ ./build.sh at flash COM3

start...
```

Note:

1. The default firmware generation path is in the sdk/bin/PRJ_NAME/ folder;
2. Note that PRJ\_NAME should not be entered with "/" after the folder, otherwise the compilation will fail.