/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2011 Oswald Buddenhagen <ossi@users.sf.net>
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

#include "config.h"

#include "sync.h"

#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <pwd.h>
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

store_conf_t *stores;

#define ARG_OPTIONAL 0
#define ARG_REQUIRED 1

static char *
get_arg( conffile_t *cfile, int required, int *comment )
{
	char *ret, *p, *t;
	int escaped, quoted;
	char c;

	p = cfile->rest;
	assert( p );
	while ((c = *p) && isspace( (unsigned char) c ))
		p++;
	if (!c || c == '#') {
		if (comment)
			*comment = (c == '#');
		if (required) {
			error( "%s:%d: parameter missing\n", cfile->file, cfile->line );
			cfile->err = 1;
		}
		ret = 0;
	} else {
		for (escaped = 0, quoted = 0, ret = t = p; c; c = *p) {
			p++;
			if (escaped && c >= 32) {
				escaped = 0;
				*t++ = c;
			} else if (c == '\\')
				escaped = 1;
			else if (c == '"')
				quoted ^= 1;
			else if (!quoted && isspace( (unsigned char) c ))
				break;
			else
				*t++ = c;
		}
		*t = 0;
		if (escaped) {
			error( "%s:%d: unterminated escape sequence\n", cfile->file, cfile->line );
			cfile->err = 1;
			ret = 0;
		}
		if (quoted) {
			error( "%s:%d: missing closing quote\n", cfile->file, cfile->line );
			cfile->err = 1;
			ret = 0;
		}
	}
	cfile->rest = p;
	return ret;
}

int
parse_bool( conffile_t *cfile )
{
	if (!strcasecmp( cfile->val, "yes" ) ||
	    !strcasecmp( cfile->val, "true" ) ||
	    !strcasecmp( cfile->val, "on" ) ||
	    !strcmp( cfile->val, "1" ))
		return 1;
	if (strcasecmp( cfile->val, "no" ) &&
	    strcasecmp( cfile->val, "false" ) &&
	    strcasecmp( cfile->val, "off" ) &&
	    strcmp( cfile->val, "0" )) {
		error( "%s:%d: invalid boolean value '%s'\n",
		       cfile->file, cfile->line, cfile->val );
		cfile->err = 1;
	}
	return 0;
}

int
parse_int( conffile_t *cfile )
{
	char *p;
	int ret;

	ret = strtol( cfile->val, &p, 10 );
	if (*p) {
		error( "%s:%d: invalid integer value '%s'\n",
		       cfile->file, cfile->line, cfile->val );
		cfile->err = 1;
		return 0;
	}
	return ret;
}

int
parse_size( conffile_t *cfile )
{
	char *p;
	int ret;

	ret = strtol (cfile->val, &p, 10);
	if (*p == 'k' || *p == 'K')
		ret *= 1024, p++;
	else if (*p == 'm' || *p == 'M')
		ret *= 1024 * 1024, p++;
	if (*p == 'b' || *p == 'B')
		p++;
	if (*p) {
		fprintf (stderr, "%s:%d: invalid size '%s'\n",
		         cfile->file, cfile->line, cfile->val);
		cfile->err = 1;
		return 0;
	}
	return ret;
}

static int
getopt_helper( conffile_t *cfile, int *cops, channel_conf_t *conf )
{
	char *arg;

	if (!strcasecmp( "Sync", cfile->cmd )) {
		arg = cfile->val;
		do
			if (!strcasecmp( "Push", arg ))
				*cops |= XOP_PUSH;
			else if (!strcasecmp( "Pull", arg ))
				*cops |= XOP_PULL;
			else if (!strcasecmp( "ReNew", arg ))
				*cops |= OP_RENEW;
			else if (!strcasecmp( "New", arg ))
				*cops |= OP_NEW;
			else if (!strcasecmp( "Delete", arg ))
				*cops |= OP_DELETE;
			else if (!strcasecmp( "Flags", arg ))
				*cops |= OP_FLAGS;
			else if (!strcasecmp( "PullReNew", arg ))
				conf->ops[S] |= OP_RENEW;
			else if (!strcasecmp( "PullNew", arg ))
				conf->ops[S] |= OP_NEW;
			else if (!strcasecmp( "PullDelete", arg ))
				conf->ops[S] |= OP_DELETE;
			else if (!strcasecmp( "PullFlags", arg ))
				conf->ops[S] |= OP_FLAGS;
			else if (!strcasecmp( "PushReNew", arg ))
				conf->ops[M] |= OP_RENEW;
			else if (!strcasecmp( "PushNew", arg ))
				conf->ops[M] |= OP_NEW;
			else if (!strcasecmp( "PushDelete", arg ))
				conf->ops[M] |= OP_DELETE;
			else if (!strcasecmp( "PushFlags", arg ))
				conf->ops[M] |= OP_FLAGS;
			else if (!strcasecmp( "All", arg ) || !strcasecmp( "Full", arg ))
				*cops |= XOP_PULL|XOP_PUSH;
			else if (strcasecmp( "None", arg ) && strcasecmp( "Noop", arg )) {
				error( "%s:%d: invalid Sync arg '%s'\n",
				       cfile->file, cfile->line, arg );
				cfile->err = 1;
			}
		while ((arg = get_arg( cfile, ARG_OPTIONAL, 0 )));
		conf->ops[M] |= XOP_HAVE_TYPE;
	} else if (!strcasecmp( "Expunge", cfile->cmd )) {
		arg = cfile->val;
		do
			if (!strcasecmp( "Both", arg ))
				*cops |= OP_EXPUNGE;
			else if (!strcasecmp( "Master", arg ))
				conf->ops[M] |= OP_EXPUNGE;
			else if (!strcasecmp( "Slave", arg ))
				conf->ops[S] |= OP_EXPUNGE;
			else if (strcasecmp( "None", arg )) {
				error( "%s:%d: invalid Expunge arg '%s'\n",
				       cfile->file, cfile->line, arg );
				cfile->err = 1;
			}
		while ((arg = get_arg( cfile, ARG_OPTIONAL, 0 )));
		conf->ops[M] |= XOP_HAVE_EXPUNGE;
	} else if (!strcasecmp( "Create", cfile->cmd )) {
		arg = cfile->val;
		do
			if (!strcasecmp( "Both", arg ))
				*cops |= OP_CREATE;
			else if (!strcasecmp( "Master", arg ))
				conf->ops[M] |= OP_CREATE;
			else if (!strcasecmp( "Slave", arg ))
				conf->ops[S] |= OP_CREATE;
			else if (strcasecmp( "None", arg )) {
				error( "%s:%d: invalid Create arg '%s'\n",
				       cfile->file, cfile->line, arg );
				cfile->err = 1;
			}
		while ((arg = get_arg( cfile, ARG_OPTIONAL, 0 )));
		conf->ops[M] |= XOP_HAVE_CREATE;
	} else if (!strcasecmp( "SyncState", cfile->cmd ))
		conf->sync_state = expand_strdup( cfile->val );
	else if (!strcasecmp( "CopyArrivalDate", cfile->cmd ))
		conf->use_internal_date = parse_bool( cfile );
	else if (!strcasecmp( "MaxMessages", cfile->cmd ))
		conf->max_messages = parse_int( cfile );
	else if (!strcasecmp( "ExpireUnread", cfile->cmd ))
		conf->expire_unread = parse_bool( cfile );
	else
		return 0;
	return 1;
}

int
getcline( conffile_t *cfile )
{
	int comment;

	while (fgets( cfile->buf, cfile->bufl, cfile->fp )) {
		cfile->line++;
		cfile->rest = cfile->buf;
		if (!(cfile->cmd = get_arg( cfile, ARG_OPTIONAL, &comment ))) {
			if (comment)
				continue;
			return 1;
		}
		if (!(cfile->val = get_arg( cfile, ARG_REQUIRED, 0 )))
			continue;
		return 1;
	}
	return 0;
}

/* XXX - this does not detect None conflicts ... */
int
merge_ops( int cops, int ops[] )
{
	int aops;

	aops = ops[M] | ops[S];
	if (ops[M] & XOP_HAVE_TYPE) {
		if (aops & OP_MASK_TYPE) {
			if (aops & cops & OP_MASK_TYPE) {
			  cfl:
				error( "Conflicting Sync args specified.\n" );
				return 1;
			}
			ops[M] |= cops & OP_MASK_TYPE;
			ops[S] |= cops & OP_MASK_TYPE;
			if (cops & XOP_PULL) {
				if (ops[S] & OP_MASK_TYPE)
					goto cfl;
				ops[S] |= OP_MASK_TYPE;
			}
			if (cops & XOP_PUSH) {
				if (ops[M] & OP_MASK_TYPE)
					goto cfl;
				ops[M] |= OP_MASK_TYPE;
			}
		} else if (cops & (OP_MASK_TYPE|XOP_MASK_DIR)) {
			if (!(cops & OP_MASK_TYPE))
				cops |= OP_MASK_TYPE;
			else if (!(cops & XOP_MASK_DIR))
				cops |= XOP_PULL|XOP_PUSH;
			if (cops & XOP_PULL)
				ops[S] |= cops & OP_MASK_TYPE;
			if (cops & XOP_PUSH)
				ops[M] |= cops & OP_MASK_TYPE;
		}
	}
	if (ops[M] & XOP_HAVE_EXPUNGE) {
		if (aops & cops & OP_EXPUNGE) {
			error( "Conflicting Expunge args specified.\n" );
			return 1;
		}
		ops[M] |= cops & OP_EXPUNGE;
		ops[S] |= cops & OP_EXPUNGE;
	}
	if (ops[M] & XOP_HAVE_CREATE) {
		if (aops & cops & OP_CREATE) {
			error( "Conflicting Create args specified.\n" );
			return 1;
		}
		ops[M] |= cops & OP_CREATE;
		ops[S] |= cops & OP_CREATE;
	}
	return 0;
}

int
load_config( const char *where, int pseudo )
{
	conffile_t cfile;
	store_conf_t *store, **storeapp = &stores;
	channel_conf_t *channel, **channelapp = &channels;
	group_conf_t *group, **groupapp = &groups;
	string_list_t *chanlist, **chanlistapp;
	char *arg, *p;
	int len, cops, gcops, max_size, ms, i;
	char path[_POSIX_PATH_MAX];
	char buf[1024];

	if (!where) {
		assert( !pseudo );
		nfsnprintf( path, sizeof(path), "%s/." EXE "rc", Home );
		cfile.file = path;
	} else
		cfile.file = where;

	if (!pseudo)
		info( "Reading configuration file %s\n", cfile.file );

	if (!(cfile.fp = fopen( cfile.file, "r" ))) {
		sys_error( "Cannot open config file '%s'", cfile.file );
		return 1;
	}
	buf[sizeof(buf) - 1] = 0;
	cfile.buf = buf;
	cfile.bufl = sizeof(buf) - 1;
	cfile.line = 0;
	cfile.err = 0;

	gcops = 0;
	global_conf.expire_unread = -1;
  reloop:
	while (getcline( &cfile )) {
		if (!cfile.cmd)
			continue;
		for (i = 0; i < N_DRIVERS; i++)
			if (drivers[i]->parse_store( &cfile, &store )) {
				if (store) {
					if (!store->max_size)
						store->max_size = INT_MAX;
					*storeapp = store;
					storeapp = &store->next;
					*storeapp = 0;
				}
				goto reloop;
			}
		if (!strcasecmp( "Channel", cfile.cmd ))
		{
			channel = nfcalloc( sizeof(*channel) );
			channel->name = nfstrdup( cfile.val );
			channel->max_messages = global_conf.max_messages;
			channel->expire_unread = global_conf.expire_unread;
			channel->use_internal_date = global_conf.use_internal_date;
			cops = 0;
			max_size = -1;
			while (getcline( &cfile ) && cfile.cmd) {
				if (!strcasecmp( "MaxSize", cfile.cmd ))
					max_size = parse_size( &cfile );
				else if (!strcasecmp( "Pattern", cfile.cmd ) ||
				         !strcasecmp( "Patterns", cfile.cmd ))
				{
					arg = cfile.val;
					do
						add_string_list( &channel->patterns, arg );
					while ((arg = get_arg( &cfile, ARG_OPTIONAL, 0 )));
				}
				else if (!strcasecmp( "Master", cfile.cmd )) {
					ms = M;
					goto linkst;
				} else if (!strcasecmp( "Slave", cfile.cmd )) {
					ms = S;
				  linkst:
					if (*cfile.val != ':' || !(p = strchr( cfile.val + 1, ':' ))) {
						error( "%s:%d: malformed mailbox spec\n",
						       cfile.file, cfile.line );
						cfile.err = 1;
						continue;
					}
					*p = 0;
					for (store = stores; store; store = store->next)
						if (!strcmp( store->name, cfile.val + 1 )) {
							channel->stores[ms] = store;
							goto stpcom;
						}
					error( "%s:%d: unknown store '%s'\n",
					       cfile.file, cfile.line, cfile.val + 1 );
					cfile.err = 1;
					continue;
				  stpcom:
					if (*++p)
						channel->boxes[ms] = nfstrdup( p );
				} else if (!getopt_helper( &cfile, &cops, channel )) {
					error( "%s:%d: unknown keyword '%s'\n", cfile.file, cfile.line, cfile.cmd );
					cfile.err = 1;
				}
			}
			if (!channel->stores[M]) {
				error( "channel '%s' refers to no master store\n", channel->name );
				cfile.err = 1;
			} else if (!channel->stores[S]) {
				error( "channel '%s' refers to no slave store\n", channel->name );
				cfile.err = 1;
			} else if (merge_ops( cops, channel->ops ))
				cfile.err = 1;
			else {
				if (max_size >= 0) {
					if (!max_size)
						max_size = INT_MAX;
					channel->stores[M]->max_size = channel->stores[S]->max_size = max_size;
				}
				*channelapp = channel;
				channelapp = &channel->next;
			}
		}
		else if (!strcasecmp( "Group", cfile.cmd ))
		{
			group = nfmalloc( sizeof(*group) );
			group->name = nfstrdup( cfile.val );
			*groupapp = group;
			groupapp = &group->next;
			*groupapp = 0;
			chanlistapp = &group->channels;
			*chanlistapp = 0;
			while ((arg = get_arg( &cfile, ARG_OPTIONAL, 0 ))) {
			  addone:
				len = strlen( arg );
				chanlist = nfmalloc( sizeof(*chanlist) + len );
				memcpy( chanlist->string, arg, len + 1 );
				*chanlistapp = chanlist;
				chanlistapp = &chanlist->next;
				*chanlistapp = 0;
			}
			while (getcline( &cfile )) {
				if (!cfile.cmd)
					goto reloop;
				if (!strcasecmp( "Channel", cfile.cmd ) ||
				    !strcasecmp( "Channels", cfile.cmd ))
				{
					arg = cfile.val;
					goto addone;
				}
				else
				{
					error( "%s:%d: unknown keyword '%s'\n",
					       cfile.file, cfile.line, cfile.cmd );
					cfile.err = 1;
				}
			}
			break;
		}
		else if (!strcasecmp( "FSync", cfile.cmd ))
		{
			UseFSync = parse_bool( &cfile );
		}
		else if (!getopt_helper( &cfile, &gcops, &global_conf ))
		{
			error( "%s:%d: unknown section keyword '%s'\n",
			       cfile.file, cfile.line, cfile.cmd );
			cfile.err = 1;
			while (getcline( &cfile ))
				if (!cfile.cmd)
					goto reloop;
			break;
		}
	}
	fclose (cfile.fp);
	cfile.err |= merge_ops( gcops, global_conf.ops );
	if (!global_conf.sync_state)
		global_conf.sync_state = expand_strdup( "~/." EXE "/" );
	if (!cfile.err && pseudo)
		unlink( where );
	return cfile.err;
}
