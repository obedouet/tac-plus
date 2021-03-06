#! /usr/bin/perl

# convert a passwd(5) and optional supplementary file into the new
# file format

# Please NOTE:  None of the TACACS code available here comes with any
# warranty or support.
# Copyright (c) 1995-1998 by Cisco systems, Inc.
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose and without fee is hereby granted, provided that this
# copyright and permission notice appear on all copies of the software and
# supporting documentation, the name of Cisco Systems, Inc. not be used
# in advertising or publicity pertaining to distribution of the
# program without specific prior permission, and notice be given
# in supporting documentation that modification, copying and distribution is by
# permission of Cisco Systems, Inc.   
# 
# Cisco Systems, Inc. makes no representations about the suitability of this
# software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS IS''
# AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
# LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE. 

die 'Usage: convert.pl <password file> [-g] [ <supplementary file> ]' 
    if $#ARGV < 0;

$pwfile = '';
$supfile  = '';
%sup = ();
$acl_valid = 0;  # is acl valid in gid field?

$pwfile = shift(@ARGV);
while ($#ARGV >= 0) {
    local($arg) = shift(@ARGV);
    $acl_valid++, next if ($arg eq '-g');
    $supfile = $arg;
}

if ($supfile) {
    open(SUP, $supfile) || die "Can't read $supfile -- $!";
    while(<SUP>) {
	next if /^#/;
	chop;

	local($user, $inacl, $outacl, $arap, $chap) = split(/:/);

	if (defined $sup{$user,'user'}) {
	    die "User $user is multiply defined on lines $sup{$user,'user'} and $. of $supfile";
	}
	$users{$user} = 1;
	$sup{$user,'user'} = $.;
	$sup{$user,'inacl'} = $inacl;
	$sup{$user,'outacl'} = $outacl;
	$sup{$user,'arap'} = $arap;
	$sup{$user,'chap'} = $chap;
    }
    close(SUP);
}

open(PASSWD, $pwfile) || die "Can't read $pwfile -- $!";

while(<PASSWD>) {
    chop;
    next if ($_ eq '');

    local($user, $pass, $uid, $gid, $gcos, $home, $exp) = split(/:/);

    $users{$user} = 2;

    print "user = $user {\n";
    print "    login = des $pass\n";
    if (!$acl_valid) {
	print "    member = $gid\n";
	$groups{$gid}++;
    }
    if ($gcos) {
	if ($gcos =~ /[ 	]/) {
	    print "    name = \"$gcos\"\n";
	} else {
	    print "    name = $gcos\n";
	}
    }

    if ($exp =~ /\S+\s+\d+\s+\d+/) {
	print "    expires = \"$exp\"\n";
    }

    if ($acl_valid) {
	print "    service = exec {\n";
	print "        acl = $gid\n";
	print "    }\n";
    }

    local($outacl) = $sup{$user,'outacl'};
    local($inacl) = $sup{$user,'inacl'};
    if ($inacl ne '' || $outacl ne '') {
	print "    service = slip {\n";
	print "	inacl = $inacl\n" if $inacl ne '';
	print "	outacl = $outacl\n" if $outacl ne '';
	print "    }\n";

	print "    service = ppp protocol = ip {\n";
	print "	inacl = $inacl\n" if $inacl ne '';
	print "	outacl = $outacl\n" if $outacl ne '';
	print "    }\n";
    }

    print "    arap = $sup{$user,'arap'}\n" if $sup{$user,'arap'} ne '';
    print "    chap = $sup{$user,'chap'}\n" if $sup{$user,'chap'} ne '';
    print "}\n";
}

close(PASSWD);

foreach $user (keys %users) {
    next if $users{$user} != 1;
    # This user only in supfile
    print "user = $user {\n";
    local($outacl) = $sup{$user,'outacl'};
    local($inacl) = $sup{$user,'inacl'};
    if ($inacl ne '' || $outacl ne '') {
	print "    service = slip {\n";
	print "	inacl = $inacl\n" if $inacl ne '';
	print "	outacl = $outacl\n" if $outacl ne '';
	print "    }\n";

	print "    service = ppp protocol = ip {\n";
	print "	inacl = $inacl\n" if $inacl ne '';
	print "	outacl = $outacl\n" if $outacl ne '';
	print "    }\n";
    }

    print "    arap = $sup{$user,'arap'}\n" if $sup{$user,'arap'} ne '';
    print "    chap = $sup{$user,'chap'}\n" if $sup{$user,'chap'} ne '';
    print "}\n";
}

exit 0 if ($acl_valid);

foreach $group (keys %groups) {
    print "group = $group { }\n";
}



