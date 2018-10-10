一键配网模式设置说明：
1.编译配置项说明
1）UDP配网配置项
#define TLS_CONFIG_UDP_ONE_SHOT          ONESHOT_ON

(1)WinnerMicro ONSHOT
#define TLS_CONFIG_UDP_LSD_ONESHOT      (ONESHOT_ON&& TLS_CONFIG_UDP_ONE_SHOT)

(2)AIRKISS配网
#define TLS_CONFIG_AIRKISS_MODE_ONESHOT (ONESHOT_ON && TLS_CONFIG_UDP_ONE_SHOT)

2）AP配网配置项
#define TLS_CONFIG_AP_MODE_ONESHOT      (ONESHOT_ON)
#define TLS_CONFIG_WEB_SERVER_MODE      (CFG_ON&&TLS_CONFIG_AP_MODE_ONESHOT)   /*WEB SERVER配网*/
#define TLS_CONFIG_SOCKET_MODE          (CFG_ON &&TLS_CONFIG_AP_MODE_ONESHOT)  /*SOCKET SERVER配网*/

2.配网调用的API说明
void tls_wifi_set_oneshot_config_mode(u8 flag);
void tls_wifi_set_oneshot_flag(u8 flag);
要设置不同的配网模式需要通过上面的两个API进行。

1)UDP和AIRKISS配网模式：
tls_wifi_set_oneshot_config_mode(0);
tls_wifi_set_oneshot_flag(1);

2)AP socket配网模式：
tls_wifi_set_oneshot_config_mode(1);
tls_wifi_set_oneshot_flag(1);

3)AP WEB SERVER配网模式：
tls_wifi_set_oneshot_config_mode(2);
tls_wifi_set_oneshot_flag(1);