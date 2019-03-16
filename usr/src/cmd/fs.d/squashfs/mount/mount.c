/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <locale.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <fslib.h>



int
main(int argc, char *argv[])
{
	char *mnt_special;
	char *mnt_mountp;

	mnt_special = argv[1];
	mnt_mountp = argv[2];


	if (mount(mnt_special, mnt_mountp, MS_DATA, "squashfs",
	    NULL, 0, NULL, 0)) {
		if (errno == EBUSY) {
			(void) fprintf(stderr, gettext(
			    "mount: %s is already mounted or %s is busy\n"),
			    mnt_special, mnt_mountp);
		} else if (errno == EINVAL) {
			(void) fprintf(stderr, gettext(
			    "mount: %s is not a DOS filesystem.\n"),
			    mnt_special);
		} else {
			perror("mount");
		}
		exit(32);
	}

	return (0);

}
