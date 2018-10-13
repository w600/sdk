//
//  SmartConfigViewController.m
//  OneShotConfig
//
//  Created by codebat on 15/1/22.
//  Copyright (c) 2015年 Winnermicro. All rights reserved.
//


#import "OneShotConfigViewController.h"
#import <SystemConfiguration/CaptiveNetwork.h>
#import "AppDelegate.h"
#import "OneShotConfig.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>
#import <dlfcn.h>

#define USE_TIMEOUT_INTERFACE  1

@interface TaskInfo : NSObject
    @property (nonatomic, copy) NSString *ssid;
    @property (nonatomic, copy) NSString *password;
@end

@implementation TaskInfo

- (id) initWithParams:(NSString *) ssidName andPwd: (NSString *) pwd
{
    self = [super init];
    if (self)
    {
        self.ssid = ssidName;
        self.password = pwd;
    }
    return self;
}

@end

@implementation OneshotConfigViewController

NSThread *thread1;
NSThread *thread2;

NSTimer *timer;

- (void)viewDidLoad
{
    [super viewDidLoad];
    NSLog(@"加载view");
    tview.hidden=YES;
    [self performSelector:@selector(dataInit)];
    
    [self.navigationItem setHidesBackButton:YES];
    self.activityIndicate.hidesWhenStopped = YES;
    self.networkPassword.tag = Tag_wifiPassword;
    self.networkPassword.delegate = self;
    self.networkPassword.returnKeyType = UIReturnKeyDone;
    self.networkPassword.secureTextEntry = NO;
    self.networkName.tag = Tag_wifiName;
    self.networkName.delegate = self;
    self.networkName.returnKeyType = UIReturnKeyDone;
    [self.networkName setBackgroundColor:[UIColor whiteColor]];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateUI) name:UIApplicationDidBecomeActiveNotification object:[UIApplication sharedApplication]];
    //程序将进入后台时，应关闭socket套接字
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(suspendApp) name:
        UIApplicationWillResignActiveNotification object:[UIApplication sharedApplication]];
    //程序将进入前台时执行，再次检查是否连接WIFI
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(resumeApp) name:
        UIApplicationWillEnterForegroundNotification object:[UIApplication sharedApplication]];
    
    self.networkName.text = [[NSUserDefaults standardUserDefaults] objectForKey:@"SSIDINFO"];
    [self.networkName addTarget:self action:@selector(textFieldDidChange:) forControlEvents:UIControlEventEditingChanged];
    
    [self.networkPassword addTarget:self action:@selector(textFieldDidChange:) forControlEvents:UIControlEventEditingChanged];
    
    timer = [NSTimer scheduledTimerWithTimeInterval:3 target:self selector:@selector(updateWIFIName) userInfo:nil repeats:YES];
}
-(void)dataInit{
    arr=[[NSMutableArray alloc] init];
}
-(void)checkIsWIFI
{
    //确保断网超时30秒后，手机仍未自动联网。用户通过设置设置网络再切到应用后将btnstartconfig的状态设置为可用
    self.btnStartConfig.enabled = YES;
//    NSString *ssid = [[NSUserDefaults standardUserDefaults] objectForKey:@"SSIDINFO"];
//    ssid = [[NSUserDefaults standardUserDefaults] objectForKey:@"SSIDINFO"];
    NSString *ssid = [self getWIFIName];
    if (ssid == nil || [ssid isEqualToString:@""])
    {
        UIAlertView *alert = [[UIAlertView alloc]initWithTitle:nil message:@"请检查你的网络连接" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
        [alert show];
    }
}

-(void)updateUI
{
    self.networkName.text = [[NSUserDefaults standardUserDefaults] objectForKey:@"SSIDINFO"];
}
-(void)suspendApp
{
    if ([self.btnStartConfig.titleLabel.text isEqualToString:@"停止"]) {
        [self smartConfig:nil];
    }
}
-(void)resumeApp
{
    //接收到UIApplicationWillResignActiveNotification通知后，resumeApp方法有时会被多次调用。原因不大明确
    //查找到原因为view页面来回切换时，没有做释放，没切换一次应用就新开一个view
    NSLog(@"继续queue");
    [self checkIsWIFI];
}
- (void)textFieldDidChange:(UITextField *)textField
{
    if (self.networkName == textField) {
        if (textField.text.length > 32) {
            textField.text = [textField.text substringToIndex:32];
        }
    }
    else{
        if (textField.text.length > 64) {
            textField.text = [textField.text substringToIndex:64];
        }
    }
}
//校验密码中是否有非ASCII码字符
-(BOOL)passwdIsValidate
{
    NSInteger strlen = [self.networkPassword.text length];
    NSInteger datalen = [[self.networkPassword.text dataUsingEncoding:NSUTF8StringEncoding] length];
    if (strlen != datalen) {
        return false;
    }
    return true;
}
- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
}

- (IBAction)secureText:(id)sender{
    
    if (self.btnSecureText.selected) {
       [self.btnSecureText setTitle:@"显示密码" forState:UIControlStateNormal];
        self.networkPassword.secureTextEntry = NO;
    } else {
       [self.btnSecureText setTitle:@"隐藏密码" forState:UIControlStateNormal];
        self.networkPassword.secureTextEntry = YES;
    }
    self.btnSecureText.selected = !self.btnSecureText.selected;
}

- (IBAction)loseFirstResponser:(id)sender {
    [self.networkName resignFirstResponder];
    [self.networkPassword becomeFirstResponder];
}
- (void) postStop
{
    //停止配置后开启timer
    [timer setFireDate:[NSDate distantPast]];
    [self.btnStartConfig setTitle:@"一键配置" forState:UIControlStateNormal];
    [self.activityIndicate stopAnimating];
    [self.networkPassword setEnabled:YES];
}

-(void)sendData:(TaskInfo *) ti
{
#if !USE_TIMEOUT_INTERFACE
    @autoreleasepool {
        while (1)
        {
            if ([NSThread currentThread].isCancelled)
            {
                [self performSelectorOnMainThread:@selector(postStop) withObject:self waitUntilDone:NO];
                [communication stopConfig];
                [NSThread exit];
            }
            else
            {
                //配网中
                int status=[communication startConfig:ti.ssid pwd:ti.password];
                NSLog(@"startConfig ret %d", status);
                if ( status == -1)
                {
                    [[NSThread currentThread] cancel];
                }
            }
        }
    }
#else
    [communication start:ti.ssid key:ti.password timeout:60];
    [self performSelectorOnMainThread:@selector(postStop) withObject:self waitUntilDone:NO];
    [communication stop];
#endif
}

- (IBAction)smartConfig:(id)sender
{
    if (self.networkName.text == nil || [self.networkName.text isEqualToString:@""] ||[self fetchSSIDInfo] == nil)
    {
        UIAlertView *alert = [[UIAlertView alloc]initWithTitle:nil message:@"请检查你的网络连接" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil, nil];
        [alert show];
        return;
    }
    else if (true != [self passwdIsValidate])
    {
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"错误" message:@"密码中不能包括中文字符" delegate:self cancelButtonTitle:@"确定" otherButtonTitles:nil];
        [alert show];
        return;
    }
    else
    {
        if ([self.btnStartConfig.titleLabel.text isEqualToString:@"一键配置"])
        {
            communication = [[OneShotConfig alloc] init];
            //开始配置时停止timer
            [timer setFireDate:[NSDate distantFuture]];
            [self.btnStartConfig setTitle:@"停止" forState:UIControlStateNormal];
            [self.activityIndicate startAnimating];
            [self.networkPassword setEnabled:NO];
            
            [arr removeAllObjects];
            tview.hidden=YES;
            //NSLog(@"线程开启");
            TaskInfo * ti = [[TaskInfo alloc] initWithParams:self.networkName.text andPwd:self.networkPassword.text];
            thread1 = [[NSThread alloc] initWithTarget:self selector:@selector(receiveData) object:nil];
            thread2=[[NSThread alloc] initWithTarget:self selector:@selector(sendData:) object:ti];
            [thread1 start];
            [thread2 start];
        }
        else if([self.btnStartConfig.titleLabel.text isEqualToString:@"停止"])
        {
            [thread1 cancel];
            [thread2 cancel];
#if !USE_TIMEOUT_INTERFACE
            [communication stopConfig];//终止当前调用中UDP包的发送
#else
            [communication stop];
#endif
        }
        else{}
    }
}
-(void)receiveData
{
    struct sockaddr_in dest;
    int length;
    int len=sizeof(int);
    NSData *data=[[NSData alloc] init];
    int sockfd=-1;
    char buffer[512];
    fd_set rfd;                     // 描述符集 这个将用来测试有没有一个可用的连接
    struct timeval timeout;
    
    timeout.tv_sec = 2;                //等下select用到这个
    timeout.tv_usec=0;
    
    
    sockfd = socket(AF_INET,SOCK_DGRAM,0);
    if(sockfd >= 0){
        memset(&dest,0,sizeof(struct sockaddr_in));
        dest.sin_family=AF_INET;
        dest.sin_addr.s_addr=htonl(INADDR_ANY);
        dest.sin_port=htons(65534);
        int dest_len=sizeof(struct sockaddr_in);
        getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char*)&length, (socklen_t*)&len);
        NSLog(@"length=%d",length);
        
        int kOn = 1;
        int err=setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &kOn, sizeof(kOn));
        NSLog(@"setsockopt的值为%d",err);
        err=bind(sockfd,(const struct sockaddr*)&dest,sizeof(dest));
        NSLog(@"bind的值为%d",err);
        
        if(err==0){
            while(![[NSThread currentThread] isCancelled]){
                //int result=recv(sockfd,buffer,sizeof(buffer),0);
                
                FD_ZERO(&rfd);                     //总是这样先清空一个描述符集
                FD_SET(sockfd, &rfd);
                if(select(sockfd+1,&rfd,0,0, &timeout)==0)
                {
                    continue;
                }
                int result=(int)recvfrom(sockfd, buffer, sizeof(buffer),0,(struct sockaddr*)&dest,(socklen_t*)&dest_len);
                NSLog(@"RESULT的值为%d",result);
                if(result>0){
                    
                    data=[NSData  dataWithBytes:buffer length:result];
                    NSLog(@"data=%@",data);
                }
                //到主线程改变列表数据；
                [self performSelectorOnMainThread:@selector(showTextView:) withObject:data waitUntilDone:YES];
            }
        }
        
        close(sockfd);
        sockfd = -1;
    }
    NSLog(@"exit thread receive!");
    [NSThread exit];
}

//主线程方法：更新接收mac地址，实现[tview reloadData];
-(void)showTextView:(NSData*)data
{
    NSMutableString *currentContent=[[NSMutableString alloc] init];
    Byte *byte;
    byte=(Byte*)[data bytes];
    int i;
    
    for(int i=0;i<[data length];i++){
        
        [currentContent appendFormat:@"%x",byte[i]&0xff ];
        if(i<[data length]-1){
            [currentContent appendFormat:@":"];
        }
    }
    for(i = 0; i < [arr count]; i++)
    {
        if([currentContent isEqualToString:[arr objectAtIndex:i]])
        {
            break;
        }
    }
    if(i == [arr count])
    {
        [arr addObject:currentContent];
    }
    tview.hidden=NO;
    [tview reloadData];
}
//调用UITableViewDelegate方法；
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView{
    return 1;
}
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section{
    return [arr count];
}


-(UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    
    static NSString *CellIdentifier = @"Cell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier: CellIdentifier];
    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:CellIdentifier];
        
    }
    cell.backgroundColor=[UIColor clearColor];
    cell.textLabel.text=[arr objectAtIndex:indexPath.row];
    return cell;
}


-(void)updateSSID:(NSString *) txt
{
    if(txt == nil)
    {
        self.networkName.text = [self getWIFIName];
    }
    else
    {
        self.networkName.text = txt;
    }
}
-(void)updateWIFIName
{
    NSString *IPAddr = [self localWiFiIPAddress];
    if (IPAddr != nil) {
        //NSLog(@"更新SSID名称");
        [self performSelectorOnMainThread:@selector(updateSSID:) withObject:nil waitUntilDone:NO];
    }
    else if (IPAddr == nil || [IPAddr isEqualToString:@""])
    {
        [self performSelectorOnMainThread:@selector(updateSSID:) withObject:@"" waitUntilDone:NO];
    }
}

#pragma mark checkValidityTextField Null
- (BOOL)checkValidityTextField
{
    if ([self.networkPassword text] == nil || [[self.networkPassword text] isEqualToString:@""]) {
        
        UIAlertView *alert = [[UIAlertView alloc]initWithTitle:nil message:@"请输入密码！" delegate:self cancelButtonTitle:nil otherButtonTitles:nil, nil];
        [alert show];
        
        return NO;
    }
    return YES;
}

#pragma mark - UITextFieldDelegate Method
- (void)textFieldDidBeginEditing:(UITextField *)textField{
    
    CGRect frame = textField.frame;
    int offset = frame.origin.y + 32 - (self.view.frame.size.height - 256.0);//键盘高度216
    
    NSTimeInterval animationDuration = 0.30f;
    [UIView beginAnimations:@"ResizeForKeyboard" context:nil];
    [UIView setAnimationDuration:animationDuration];
    
    //将视图的Y坐标向上移动offset个单位，以使下面腾出地方用于软键盘的显示
    if(offset > 0)
        self.view.frame = CGRectMake(0.0f, -offset, self.view.frame.size.width, self.view.frame.size.height);
    
    [UIView commitAnimations];
}

- (void)textFieldDidEndEditing:(UITextField *)textField{
    self.view.frame =CGRectMake(0, 0, self.view.frame.size.width, self.view.frame.size.height);
    switch (textField.tag) {
            
        case Tag_wifiName:
            {
                if ([textField text] != nil && [[textField text] length]!= 0) {
                    
                }
            }
            break;
        case Tag_wifiPassword:
            {
                if ([textField text] != nil && [[textField text] length]!= 0) {
                }
            }
            break;
        default:
            break;
    }
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField
{
    [textField resignFirstResponder];
    return NO;
}

#pragma mark - touchMethod
-(void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event{
    
    [super touchesBegan:touches withEvent:event];
    
    [self allEditActionsResignFirstResponder];
}

#pragma mark - PrivateMethod
- (void)allEditActionsResignFirstResponder{
    [[self.view viewWithTag:Tag_wifiName] resignFirstResponder];
    [[self.view viewWithTag:Tag_wifiPassword] resignFirstResponder];
}
#pragma mark 控制页面的跳转
-(void)viewWillDisappear:(BOOL)animated
{
    //停止timer
    [timer setFireDate:[NSDate distantFuture]];
    NSLog(@"view消失");
    if ([self.btnStartConfig.titleLabel.text isEqualToString:@"停止"]) {
        [self smartConfig:nil];
    }
}
-(void)viewWillAppear:(BOOL)animated
{
    //记录view显示后当前网络的IP地址
    NSString * pastIPAddr = [self localWiFiIPAddress];
    
    if (pastIPAddr == nil || [pastIPAddr isEqualToString:@""]) {
        self.networkName.text = @"";
    }
    else{
        self.networkName.text = [self getWIFIName];
    }
    
    [self checkIsWIFI];
    //不管网络状态均需开启timer
    [timer setFireDate:[NSDate distantPast]];
    NSLog(@"view进来");
}

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
//获取当前WIFI名称
-(NSString*)getWIFIName
{
    NSDictionary *ifs = [self fetchSSIDInfo]; //获取sid信息。
    NSString *ssid = [ifs objectForKey:@"SSID"];//获取当前连接WIFI名称
    return ssid;
}
//获取当前网络的IP地址
- (NSString *) localWiFiIPAddress
{
    BOOL success;
    struct ifaddrs * addrs;
    const struct ifaddrs * cursor;
    
    success = getifaddrs(&addrs) == 0;
    if (success) {
        cursor = addrs;
        while (cursor != NULL) {
            // the second test keeps from picking up the loopback address
            if (cursor->ifa_addr->sa_family == AF_INET && (cursor->ifa_flags & IFF_LOOPBACK) == 0)
            {
                NSString *name = [NSString stringWithUTF8String:cursor->ifa_name];
                if ([name isEqualToString:@"en0"])  // Wi-Fi adapter
                    return [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)cursor->ifa_addr)->sin_addr)];
            }
            cursor = cursor->ifa_next;
        }
        freeifaddrs(addrs);
    }
    return nil;
}

@end
