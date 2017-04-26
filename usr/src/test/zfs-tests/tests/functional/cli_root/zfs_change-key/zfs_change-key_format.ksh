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
# 'zfs change-key -o' should change the key format.
#
# STRATEGY:
# 1. Create an encryption dataset with a passphrase key format
# 2. Unmount the dataset
# 3. Verify the key format is passphrase
# 4. Change the key format to hex
# 5. Verify the key format is hex
# 6. Attempt to reload the dataset's key
# 7. Change the key format to raw
# 8. Verify the key format is raw
# 9. Attempt to reload the dataset's key
#

verify_runnable "both"

function verify_keyformat
{
	typeset ds=$1
	typeset format=$2
	typeset fmt=$(get_prop keyformat $ds)

	if [[ "$fmt" != "$format" ]]; then
		log_fail "Expected keyformat $format, got $fmt"
	fi

	return 0
}

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
		log_must $ZFS destroy $TESTPOOL/$TESTFS1
}
log_onexit cleanup

log_assert "'zfs change-key -o' should change the key format"

log_must eval "$ECHO $PASSPHRASE | $ZFS create -o encryption=on" \
	"-o keyformat=passphrase -o keylocation=prompt $TESTPOOL/$TESTFS1"
log_must $ZFS unmount $TESTPOOL/$TESTFS1

log_must verify_keyformat $TESTPOOL/$TESTFS1 "passphrase"

log_must eval "$ECHO $HEXKEY | $ZFS change-key -o keyformat=hex" \
	"$TESTPOOL/$TESTFS1"
log_must verify_keyformat $TESTPOOL/$TESTFS1 "hex"

log_must $ZFS unload-key $TESTPOOL/$TESTFS1
log_must eval "$ECHO $HEXKEY | $ZFS load-key $TESTPOOL/$TESTFS1"

log_must eval "$ECHO $RAWKEY | $ZFS change-key -o keyformat=raw" \
	"$TESTPOOL/$TESTFS1"
log_must verify_keyformat $TESTPOOL/$TESTFS1 "raw"

log_must $ZFS unload-key $TESTPOOL/$TESTFS1
log_must eval "$ECHO $RAWKEY | $ZFS load-key $TESTPOOL/$TESTFS1"

log_pass "'zfs change-key -o' changes the key format"
