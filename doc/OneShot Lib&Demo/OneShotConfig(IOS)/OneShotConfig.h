//
//  OneShotConfig.h
//  OneShotConfig

//  Created by codebat on 15/1/22.
//  Copyright (c) 2015骞?Winnermicro. All rights reserved.
//
//

#import <Foundation/Foundation.h>


@interface OneShotConfig : NSObject
/*杩斿洖锛?
 0,琛ㄧず鍙戦€佹甯哥粨鏉燂紝濡傛灉娌℃湁閰嶇疆鎴愬姛锛岄渶瑕佺户缁皟鐢ㄨ鏂规硶
 -1,琛ㄧず鐢变簬璋冪敤stop鎴栨槸stopConfig鎺ュ彛锛屼腑鏂鏂规硶
 -2,琛ㄧず鍐呴儴閿欒
 */
-(int)startConfig: (NSString*) ssid pwd: (NSString*) password;
/*涓柇startConfig鐨勯厤缃戞搷浣?
 */
-(void)stopConfig;

-(void) start: (NSString*)ssid key:(NSString*)key  timeout:(int) timeout;

-(void) stop;

@end
