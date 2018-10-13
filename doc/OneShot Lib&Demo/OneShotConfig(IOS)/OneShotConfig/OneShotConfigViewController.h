//
//  SmartConfigViewController.h
//  OneShotConfig
//
//  Created by codebat on 15/1/22.
//  Copyright (c) 2015骞?Winnermicro. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "OneShotConfig.h"
#import "MBProgressHUD.h"
//#import "GCDAsyncUdpSocket.h"

enum TAG_TEXTFIELD{
    
    Tag_wifiName = 100,
    Tag_wifiPassword
};

@interface OneshotConfigViewController : UIViewController <UITextFieldDelegate, UIAlertViewDelegate,UITableViewDelegate,UITableViewDataSource,MBProgressHUDDelegate>{
    OneShotConfig *communication;
        IBOutlet UITableView *tview;
        NSMutableArray *arr;
    }

    @property (nonatomic, weak) IBOutlet UITextField *networkName;
    @property (nonatomic, weak) IBOutlet UITextField *networkPassword;
    @property (nonatomic, weak) IBOutlet UIButton *btnSecureText;
    @property (nonatomic, weak) IBOutlet UIActivityIndicatorView *activityIndicate;
    @property (nonatomic, weak) IBOutlet UIButton *btnStartConfig;

    - (IBAction)loseFirstResponser:(id)sender;
    - (IBAction)smartConfig:(id)sender;
    - (IBAction)secureText:(id)sender;

@end
