//
//  ManualConfigViewController.h
//  OneShotConfig
//
//  Created by codebat on 15/1/22.
//  Copyright (c) 2015骞?Winnermicro. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "MBProgressHUD.h"
#import "ManualConfig.h"
//#import "seManualConfig.h"
@interface ManualConfigViewController : UIViewController <UIAlertViewDelegate, UITextFieldDelegate,MBProgressHUDDelegate>
{
    ManualConfig *tcpsockethandle;
    //seManualConfig* setcpsockethandle;
}
@property (strong, nonatomic) IBOutlet UIActivityIndicatorView *activity;

@property (strong, nonatomic) IBOutlet UITextField *networkName;
@property (strong, nonatomic) IBOutlet UITextField *networkPasswd;
@property (strong, nonatomic) IBOutlet UIButton *configBn;
@property (strong, nonatomic) IBOutlet UIButton *secureBn;
- (IBAction)configuration:(id)sender;
- (IBAction)secureText:(id)sender;


@end
