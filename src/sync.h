/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2010-2012 Oswald Buddenhagen <ossi@users.sf.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, mbsync may be linked with the OpenSSL library,
 * despite that library's more restrictive license.
 */

#ifndef SYNC_H
#define SYNC_H

#include "driver.h"

#define M 0 /* master */
#define S 1 /* slave */

#define OP_NEW             (1<<0)
#define OP_RENEW           (1<<1)
#define OP_DELETE          (1<<2)
#define OP_FLAGS           (1<<3)
#define  OP_MASK_TYPE      (OP_NEW|OP_RENEW|OP_DELETE|OP_FLAGS) /* asserted in the target ops */
#define OP_EXPUNGE         (1<<4)
#define OP_CREATE          (1<<5)
#define XOP_PUSH           (1<<6)
#define XOP_PULL           (1<<7)
#define  XOP_MASK_DIR      (XOP_PUSH|XOP_PULL)
#define XOP_HAVE_TYPE      (1<<8)
#define XOP_HAVE_EXPUNGE   (1<<9)
#define XOP_HAVE_CREATE    (1<<10)

typedef struct channel_conf {
	struct channel_conf *next;
	const char *name;
	store_conf_t *stores[2];
	const char *boxes[2];
	char *sync_state;
	string_list_t *patterns;
	int ops[2];
	unsigned max_messages; /* for slave only */
	signed char expire_unread;
	char use_internal_date;
} channel_conf_t;

typedef struct group_conf {
	struct group_conf *next;
	const char *name;
	string_list_t *channels;
} group_conf_t;

extern channel_conf_t global_conf;
extern channel_conf_t *channels;
extern group_conf_t *groups;

extern const char *str_ms[2], *str_hl[2];

#define SYNC_OK       0 /* assumed to be 0 */
#define SYNC_FAIL     1
#define SYNC_FAIL_ALL 2
#define SYNC_BAD(ms)  (4<<(ms))
#define SYNC_NOGOOD   16 /* internal */
#define SYNC_CANCELED 32 /* internal */

/* All passed pointers must stay alive until cb is called. */
void sync_boxes( store_t *ctx[], const char *names[], channel_conf_t *chan,
                 void (*cb)( int sts, void *aux ), void *aux );

#endif
