//
//  buddylist.h
//  SworIM
//
//  Created by Anurodh Pokharel on 11/21/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <monalxmpp/DataLayer.h>
@import SAMKeychain;
#import <monalxmpp/MLXMPPManager.h>
#import "TOCropViewController.h"

@interface XMPPEdit: UITableViewController <UITextFieldDelegate, UINavigationControllerDelegate, UIImagePickerControllerDelegate, UIDocumentPickerDelegate, TOCropViewControllerDelegate> {
	IBOutlet UILabel *JIDLabel;
}

@property (nonatomic, strong) NSNumber* accountID;
@property (nonatomic, strong) NSIndexPath* originIndex;

-(IBAction) save:(id) sender;

@end


