//
//  MLPresenceSettings.m
//  Monal
//
//  Created by Anurodh Pokharel on 7/29/15.
//  Copyright (c) 2015 Monal.im. All rights reserved.
//

#import "MLPresenceSettings.h"

@interface MLPresenceSettings ()

@end

@implementation MLPresenceSettings


- (void)viewDidLoad {
    [super viewDidLoad];
    // Do view setup here.
}


#pragma mark - preferences delegate

- (NSString *)identifier
{
    return self.title;
}

- (NSImage *)toolbarItemImage
{
    return [NSImage imageNamed:NSImageNameAdvanced];
}

- (NSString *)toolbarItemLabel
{
    return @"Presence";
}


@end
