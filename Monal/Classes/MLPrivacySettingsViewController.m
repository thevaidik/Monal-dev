//
//  MLPrivacySettingsViewController.m
//  Monal
//
//  Created by Friedrich Altheide on 06.08.20.
//  Copyright © 2020 Monal.im. All rights reserved.
//

#import "MLPrivacySettingsViewController.h"

@implementation MLPrivacySettingsViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    self.navigationItem.title = NSLocalizedString(@"Display Settings",@"");
   
    _settingsTable = self.tableView;
    _settingsTable.delegate = self;
    _settingsTable.dataSource = self;
    _settingsTable.backgroundView = nil;
}

-(void) viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
}

#pragma mark tableview datasource delegate
-(NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 1;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    switch (section) {
        case 0:
        {
            return NSLocalizedString(@"General", @"");
            break;
        }
        default:
        {
            return nil;
            break;
        }
    }
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    switch (section) {
        case 0:
        {
            return 4;
            break;
        }
        default:
        {
            return 0;
        }
        break;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    
    MLSettingCell* cell = [[MLSettingCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"AccountCell"];
    cell.parent= self;
   
    switch (indexPath.section) {
        case 0:
        {
            switch(indexPath.row)
            {
                case 0:
                {
                    cell.textLabel.text=NSLocalizedString(@"Show Inline Images", @"");
                    cell.detailTextLabel.text = NSLocalizedString(@"Will make a HTTP HEAD call on all links", @"");
                    cell.defaultKey = @"ShowImages";
                    cell.switchEnabled = YES;
                    break;
                }
                case 1:
                {
                    cell.textLabel.text=NSLocalizedString(@"Show Inline Geo Location", @"");
                    cell.detailTextLabel.text = @"";
                    cell.defaultKey = @"ShowGeoLocation";
                    cell.switchEnabled = YES;
                    break;
                }
                case 2:
                {
                    cell.textLabel.text = NSLocalizedString(@"Send Last Interaction Time", @"");
                    cell.detailTextLabel.text = NSLocalizedString(@"Automatically send when you were online", @"");
                    cell.defaultKey = @"SendLastUserInteraction";
                    cell.switchEnabled = YES;
                    break;
                }
                case 3:
                    {
                        cell.textLabel.text = NSLocalizedString(@"Send Typing Notifications", @"");
                        cell.detailTextLabel.text = NSLocalizedString(@"Tell my contacts when I'm typing", @"");
                        cell.defaultKey = @"SendLastChatState";
                        cell.switchEnabled = YES;
                        break;
                    }
            }
            return cell;
        }
        default:
        {
            return nil;
            break;
        }
    }

    return nil;
}

-(IBAction)close:(id)sender
{
    [self.presentingViewController dismissViewControllerAnimated:YES completion:nil];
}

@end
