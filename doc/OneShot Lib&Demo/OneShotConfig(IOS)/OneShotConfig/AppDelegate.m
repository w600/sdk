//
//  AppDelegate.m
//  OneShotConfig
//
//  Created by codebat on 15/1/22.
//  Copyright (c) 2015年 Winnermicro. All rights reserved.
//
#import "AppDelegate.h"
#import <SystemConfiguration/CaptiveNetwork.h>

#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)

@interface AppDelegate ()
-(id)fetchSSIDInfo;
@end

@implementation AppDelegate

/** Returns first non-empty SSID network info dictionary.
 *  @see CNCopyCurrentNetworkInfo */
- (NSDictionary *)fetchSSIDInfo
{
    NSArray *interfaceNames = CFBridgingRelease(CNCopySupportedInterfaces());
    //NSLog(@"%s: Supported interfaces: %@", __func__, interfaceNames);
    
    NSDictionary *SSIDInfo;
    for (NSString *interfaceName in interfaceNames) {
        SSIDInfo = CFBridgingRelease(
                                     CNCopyCurrentNetworkInfo((__bridge CFStringRef)interfaceName));
        //NSLog(@"%s: %@ => %@", __func__, interfaceName, SSIDInfo);
        
        BOOL isNotEmpty = (SSIDInfo.count > 0);
        if (isNotEmpty) {
            break;
        }
    }
    return SSIDInfo;
}

- (void)acquireNetWorkPermission {
    if(SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"10.0"))
    {
        // 1.创建url
        // 请求一个网页
        NSString *urlString = @"https://www.baidu.com";
        // 一些特殊字符编码
        urlString = [urlString stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
        NSURL *url = [NSURL URLWithString:urlString];
        
        // 2.创建请求 并：设置缓存策略为每次都从网络加载 超时时间30秒
        NSURLRequest *request = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:30];
        
        // 3.采用苹果提供的共享session
        NSURLSession *sharedSession = [NSURLSession sharedSession];
        
        // 4.由系统直接返回一个dataTask任务
        NSURLSessionDataTask *dataTask = [sharedSession dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
            // 网络请求完成之后就会执行，NSURLSession自动实现多线程
            NSLog(@"%@",[NSThread currentThread]);
            if (data && (error == nil)) {
                // 网络访问成功
                NSLog(@"data=%@",[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
            } else {
                // 网络访问失败
                NSLog(@"error=%@",error);
            }
        }];
        
        // 5.每一个任务默认都是挂起的，需要调用 resume 方法
        [dataTask resume];
    }
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    _Mpasswd = @"";
    _Musername=@"";
//    NSLog(@"localWiFiIPAddress = %@",[self localWiFiIPAddress ]);
    NSLog(@"加载加载%@",[self fetchSSIDInfo]);
    self.window.backgroundColor = [UIColor whiteColor];
    NSDictionary *ifs = [self fetchSSIDInfo]; //获取sid信息。
    NSString *ssid = [ifs objectForKey:@"SSID"];//获取当前连接WIFI名称
    [[NSUserDefaults standardUserDefaults] setObject:ssid forKey:@"SSIDINFO"];
    
    [self acquireNetWorkPermission];
    NSLog(@"i didFinishLaunching");
    return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {
    NSLog(@"i resignActive");
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    NSLog(@"i didenterBackgroud");
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    NSLog(@"i willenterforegroud");
    //用户切换到设置连接WIFI后再次进入时更新WIFI信息
    NSDictionary *ifs = [self fetchSSIDInfo]; //获取sid信息。
    NSString *ssid = [ifs objectForKey:@"SSID"];//获取当前连接WIFI名称
    [[NSUserDefaults standardUserDefaults] setObject:ssid forKey:@"SSIDINFO"];

}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    NSLog(@"didBecomActive");
}

- (void)applicationWillTerminate:(UIApplication *)application {
    NSLog(@"wiiTerminate");
}
@end
