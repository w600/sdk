//
//  ManualConfig.h
//  OneShotConfig
//
//  Created by codebat on 15/1/22.
//  Copyright (c) 2015骞?Winnermicro. All rights reserved.
//

#import <Foundation/Foundation.h>
@interface ManualConfig : NSObject
/*璁剧疆鍙敤鏉ュ搷搴旇繛鎺ヨ姹傜殑WIFI缃戠粶鍚嶇О鐨勫墠缂€锛?
 濡備互softap寮€澶达紝鍒橻ManualConfig setValidSSIDPrefix:@"softap"]
 */
+(void)setValidSSIDPrefix:(NSString*)name;
+ (instancetype)getInstance;

/*
 杩斿洖
 -1锛岃〃绀烘病鏈夎繛鎺ュ埌wifi
 -2锛岃〃绀哄綋鍓嶈繛鎺ョ綉缁滅殑SSID涓嶅锛屽簲淇敼涓哄悎閫傚墠缂€鐨凷SID
 -3锛岃〃绀鸿繛鎺CP Server瓒呮椂
 -4锛岃〃绀哄彂閫佹暟鎹秴鏃?
 0锛岃〃绀哄彂閫佹垚鍔?
 鍙戦€佸畬鍚庝細鍏抽棴tcp socket
 */

-(int)startConfig:(NSString*)ssid pwd:(NSString*)password;
@end
