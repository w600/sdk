//
//  ManualConfigViewController.m
//  OneShotConfig
//
//  Created by codebat on 15/1/22.
//  Copyright (c) 2015年 Winnermicro. All rights reserved.
//

#import "ManualConfigViewController.h"
#import <SystemConfiguration/CaptiveNetwork.h>
#import "AppDelegate.h"
@interface ManualConfigViewController ()

@end

@implementation ManualConfigViewController
MBProgressHUD *HUD;
@synthesize networkName,networkPasswd,secureBn,configBn;
static UIAlertView *alert;
int result;
//记录发送TCP状态
bool hidden = YES;
NSThread *thread;
#define SSIDPrefix @"softap"
- (void)viewDidLoad
{
    [super viewDidLoad];
    networkName.delegate = self;
    networkName.tag = 0;
    networkPasswd.delegate = self;
    networkName.tag = 1;
    [ManualConfig setValidSSIDPrefix:SSIDPrefix];
    //[seManualConfig setValidSSIDPrefix:SSIDPrefix];
    //SSID前缀区分大小写
    self.activity.hidesWhenStopped = YES;
    networkPasswd.secureTextEntry = NO;
}
- (BOOL)textField:(UITextField *)textField shouldChangeCharactersInRange:(NSRange)range replacementString:(NSString *)string

{
    
    NSInteger strLength = textField.text.length - range.length + string.length;
    if (textField == networkName) {
        return (strLength <= 32);
    }
    else{
        return (strLength <= 64);
    }
    
    
}
-(void)viewDidAppear:(BOOL)animated
{
    tcpsockethandle = [ManualConfig getInstance];
    }
- (IBAction)configuration:(id)sender {
    NSLog(@"执行点击");
    [networkPasswd resignFirstResponder];
    [self.activity startAnimating];
    
   
    if ([self fetchSSIDInfo] == nil) {
        alert = [[UIAlertView alloc] initWithTitle:nil message:@"请检查你的网络连接" delegate:self cancelButtonTitle:nil
                                 otherButtonTitles:@"确定", nil];
        [alert show];
        [self.activity stopAnimating];
    }
 
    else if (![self checkNULLTextField])
    {
        alert = [[UIAlertView alloc]initWithTitle:nil message:@"WIFI名称不能为空！" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
        [alert show];
        [self.activity stopAnimating];
        
    }
    else if (![self passwdIsValidate]) {
        alert = [[UIAlertView alloc] initWithTitle:@"错误！" message:@"密码中不能包括中文字符" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil];
        [alert show];
        [self.activity stopAnimating];
    }
    else
    {
     thread = [[NSThread alloc] initWithTarget:self selector:@selector(peizhi) object:nil];
     [thread start];
    
    
//        [self performSelectorInBackground:@selector(peizhi) withObject:nil];
    }
}
-(void)peizhi
{
    @autoreleasepool {
        NSString *ssidName = networkName.text;
        NSString *passwd = networkPasswd.text;
        result = [tcpsockethandle startConfig:ssidName pwd:passwd];
        
        if (0 == result ) {
            NSLog(@"配置成功");
            [self performSelectorOnMainThread:@selector(showSuccessMrak) withObject:nil waitUntilDone:YES];
        }
        else if (-1 == result)
        {
            NSLog(@"请连接到WIFI网络");
            [self performSelectorOnMainThread:@selector(showalertView:) withObject:[NSNumber numberWithInt:-1] waitUntilDone:NO];
//            alert = [[UIAlertView alloc]initWithTitle:nil message:@"请连接到WIFI网络！" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
//            alert.tag = -1;
//            [alert show];
            [self.activity stopAnimating];
        }
        else if (-2 == result)
        {
            NSLog(@"请连接前缀");
            [self performSelectorOnMainThread:@selector(showalertView:) withObject:[NSNumber numberWithInt:-2] waitUntilDone:NO];
//            alert = [[UIAlertView alloc]initWithTitle:nil message:[NSString stringWithFormat:@"请连接前缀为%@的WIFI网络",SSIDPrefix] delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
//            alert.tag = -2;
//            [alert show];
            [self.activity stopAnimating];
        }
        else  if(-3 == result)
        {
            NSLog(@"连接服务器请求超时");
            [self performSelectorOnMainThread:@selector(showalertView:) withObject:[NSNumber numberWithInt:-3] waitUntilDone:NO];
//            alert = [[UIAlertView alloc]initWithTitle:@"配置失败" message:@"连接服务器请求超时！" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
//            alert.tag = -3;
//            [alert show];
            [self.activity stopAnimating];
        }
        else//(-4 == result)
        {
            NSLog(@"发送数据请求超时");
            [self performSelectorOnMainThread:@selector(showalertView:) withObject:[NSNumber numberWithInt:-4] waitUntilDone:NO];
//            alert = [[UIAlertView alloc]initWithTitle:@"配置失败" message:@"发送数据请求超时！" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
//            alert.tag = -4;
//            [alert show];
            [self.activity stopAnimating];
        }
        
        [thread cancel];
        if ([NSThread currentThread].isCancelled) {
            [NSThread exit];
        }

    }
}
-(void)showalertView:(id)num
{
    if ([num integerValue] == -1) {
        alert = [[UIAlertView alloc]initWithTitle:nil message:@"请连接到WIFI网络！" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
        //            alert.tag = -1;
                    [alert show];
    }
    else if ([num integerValue] == -2)
    {
        alert = [[UIAlertView alloc]initWithTitle:nil message:[NSString stringWithFormat:@"请连接前缀为%@的WIFI网络",SSIDPrefix] delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
        //            alert.tag = -2;
                    [alert show];
    }
    else if ([num integerValue] == -3)
    {
        alert = [[UIAlertView alloc]initWithTitle:@"配置失败" message:@"连接服务器请求超时！" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
        //            alert.tag = -3;
                    [alert show];
    }
    else
    {
        alert = [[UIAlertView alloc]initWithTitle:@"配置失败" message:@"发送数据请求超时！" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
        //            alert.tag = -4;
                    [alert show];
    }
    
}
-(BOOL)passwdIsValidate
{
    NSInteger strlen = [networkPasswd.text length];
    NSInteger datalen = [[networkPasswd.text dataUsingEncoding:NSUTF8StringEncoding] length];
    if (strlen != datalen) {
        return false;
    }
    return true;
}
- (IBAction)secureText:(id)sender {
    if (secureBn.selected) {
        [secureBn setTitle:@"显示密码" forState:UIControlStateNormal];
        networkPasswd.secureTextEntry = NO;
    } else {
        [secureBn setTitle:@"隐藏密码" forState:UIControlStateNormal];
        networkPasswd.secureTextEntry = YES;
    }
    secureBn.selected = !secureBn.selected;

}
#pragma mark showConfigMark
-(void)showConfigMark
{
    if (HUD != nil) {
        HUD.hidden = YES;
        [HUD removeFromSuperview];
    }
    HUD = [[MBProgressHUD alloc] initWithView:self.view];
    [self.view addSubview:HUD];
    HUD.delegate = self;
    HUD.labelText = @"正在配置";
    [HUD showWhileExecuting:@selector(myTask) onTarget:self withObject:nil animated:YES];

}
- (void)myTask {
    sleep(8);
}
#pragma mark showFailMark
-(void)showFailMark
{
    
   if (HUD != nil) {
       HUD.hidden = YES;
       [HUD removeFromSuperview];
    }
    HUD = [[MBProgressHUD alloc] initWithView:self.view];
    [self.view addSubview:HUD];
    HUD.customView = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"37x-Failmark.png"]];
    HUD.mode = MBProgressHUDModeCustomView;
    HUD.delegate = self;
    HUD.labelText = @"配置失败!";
    [HUD show:YES];
    [HUD hide:YES afterDelay:2];
        
}
#pragma mark showSuccessMark
-(void)showSuccessMrak
{
    NSLog(@"我被调用啦！");
    if (HUD != nil) {
        HUD.hidden = YES;
        [HUD removeFromSuperview];
    }
    HUD = [[MBProgressHUD alloc] initWithView:self.view];
    [self.view addSubview:HUD];
    HUD.customView = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"37x-Checkmark.png"]];
    HUD.mode = MBProgressHUDModeCustomView;
    HUD.delegate = self;
    HUD.labelText = @"Success!";
    [HUD show:YES];
    [NSThread sleepForTimeInterval:5];
    [HUD hide:YES afterDelay:2];
    [self.activity stopAnimating];
}
#pragma mark checkValidityTextField Null
-(BOOL)checkNULLTextField
{
    if ([networkName text] == nil || [[networkName text] isEqualToString:@""]) {
        return NO;
    }
    return YES;
}

-(void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event
{
    [networkName resignFirstResponder];
    [networkPasswd resignFirstResponder];
}
- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
}
#pragma mark 调整文本框位置不被键盘遮盖
//开始编辑输入框的时候，软键盘出现，执行此事件
-(void)textFieldDidBeginEditing:(UITextField *)textField
{
    CGRect frame = networkPasswd.frame;
    int offset = frame.origin.y + 32 - (self.view.frame.size.height - 216.0);//键盘高度216
    
    NSTimeInterval animationDuration = 0.30f;
    [UIView beginAnimations:@"ResizeForKeyboard" context:nil];
    [UIView setAnimationDuration:animationDuration];
    
    //将视图的Y坐标向上移动offset个单位，以使下面腾出地方用于软键盘的显示
    if(offset > 0)
        self.view.frame = CGRectMake(0.0f, -offset, self.view.frame.size.width, self.view.frame.size.height);
    [UIView commitAnimations];

}
//当用户按下return键或者按回车键，keyboard消失
-(BOOL)textFieldShouldReturn:(UITextField *)textField
{
    [textField resignFirstResponder];
    return NO;
}
//输入框编辑完成以后，将视图恢复到原始状态
-(void)textFieldDidEndEditing:(UITextField *)textField
{
    self.view.frame =CGRectMake(0, 0, self.view.frame.size.width, self.view.frame.size.height);
    switch (textField.tag) {
            
        case 0:
        {
            if ([textField text] != nil && [[textField text] length]!= 0) {
                
            }
        }
            break;
        case 1:
        {
            if ([textField text] != nil && [[textField text] length]!= 0) {
            }
        }
            break;
        default:
            break;
    }

}
#pragma mark 检查网络连接
- (id)fetchSSIDInfo
{
    NSArray *ifs = (__bridge id)CNCopySupportedInterfaces();
//    NSLog(@"%s: Supported interfaces: %@", __func__, ifs);
    id info = nil;
    for (NSString *ifnam in ifs) {
        info = (__bridge id)CNCopyCurrentNetworkInfo((__bridge CFStringRef)ifnam);
        //        NSLog(@"ifnam=%@", ifnam);
        if (info && [info count]) {
            break;
        }
    }
    return info ;
}
-(void)viewWillDisappear:(BOOL)animated
{
    ((AppDelegate*)[UIApplication sharedApplication].delegate).Musername = networkName.text;
    ((AppDelegate*)[UIApplication sharedApplication].delegate).Mpasswd = networkPasswd.text;
    NSLog(@"view消失");
}
-(void)viewWillAppear:(BOOL)animated
{
    NSDictionary *ifs = [self fetchSSIDInfo]; //获取sid信息。
    NSString *ssid = [ifs objectForKey:@"SSID"];//获取当前连接WIFI名称
    if (ssid == nil || [ssid isEqualToString:@""])
    {
        alert = [[UIAlertView alloc]initWithTitle:nil message:@"请检查你的网络连接" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
        [alert show];
    }

    networkName.text = ((AppDelegate*)[UIApplication sharedApplication].delegate).Musername;
    networkPasswd.text = ((AppDelegate*)[UIApplication sharedApplication].delegate).Mpasswd;
    NSLog(@"ManualconfigView enter");
//    NSLog(@"全局变量cont2=%i",count2);
}
@end
