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

#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"

typedef struct conffile {
	const char *file;
	FILE *fp;
	char *buf;
	int bufl;
	int line;
	int err;
	char *cmd, *val, *rest;
} conffile_t;

int parse_bool( conffile_t *cfile );
int parse_int( conffile_t *cfile );
int parse_size( conffile_t *cfile );
int getcline( conffile_t *cfile );
int merge_ops( int cops, int ops[] );
int load_config( const char *filename, int pseudo );

#endif
