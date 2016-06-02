#!/bin/ksh -p
#
# CDDL HEADER START
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# CDDL HEADER END
#

#
# Copyright (c) 2017 Datto, Inc. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zfs_load-key/zfs_load-key_common.kshlib

#
# DESCRIPTION:
# 'zfs load-key -a' should load keys for all datasets.
#
# STRATEGY:
# 1. Create an encrypted filesystem, encrypted zvol, and an encrypted pool
# 2. Unmount all datasets and unload their keys
# 3. Attempt to load all dataset keys
# 4. Verify each dataset has its key loaded
# 5. Attempt to mount the pool and filesystem
#

verify_runnable "both"

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
		log_must $ZFS destroy $TESTPOOL/$TESTFS1
	datasetexists $TESTPOOL/zvol && log_must $ZFS destroy $TESTPOOL/zvol
	poolexists $TESTPOOL1 && log_must destroy_pool $TESTPOOL1
}
log_onexit cleanup

log_assert "'zfs load-key -a' should load keys for all datasets"

log_must eval "$ECHO $PASSPHRASE1 > /$TESTPOOL/pkey"
log_must $ZFS create -o encryption=on -o keyformat=passphrase \
	-o keylocation=file:///$TESTPOOL/pkey $TESTPOOL/$TESTFS1

log_must $ZFS create -V 64M -o encryption=on -o keyformat=passphrase \
	-o keylocation=file:///$TESTPOOL/pkey $TESTPOOL/zvol

typeset DISK2="$($ECHO $DISKS | $AWK '{ print $2}')"
log_must $ZPOOL create -O encryption=on -O keyformat=passphrase \
	-O keylocation=file:///$TESTPOOL/pkey $TESTPOOL1 $DISK2

log_must $ZFS unmount $TESTPOOL/$TESTFS1
log_must $ZFS unload-key $TESTPOOL/$TESTFS1

log_must $ZFS unload-key $TESTPOOL/zvol

log_must $ZFS unmount $TESTPOOL1
log_must $ZFS unload-key $TESTPOOL1

log_must $ZFS load-key -a

log_must key_available $TESTPOOL1
log_must key_available $TESTPOOL/zvol
log_must key_available $TESTPOOL/$TESTFS1

log_must $ZFS mount $TESTPOOL1
log_must $ZFS mount $TESTPOOL/$TESTFS1

log_pass "'zfs load-key -a' loads keys for all datasets"
