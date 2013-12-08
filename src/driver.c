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

#include "driver.h"

#include <stdlib.h>
#include <string.h>

driver_t *drivers[N_DRIVERS] = { &maildir_driver, &imap_driver };

void
free_generic_messages( message_t *msgs )
{
	message_t *tmsg;

	for (; msgs; msgs = tmsg) {
		tmsg = msgs->next;
		free( msgs );
	}
}

void
parse_generic_store( store_conf_t *store, conffile_t *cfg )
{
	if (!strcasecmp( "Trash", cfg->cmd )) {
		store->trash = nfstrdup( cfg->val );
	} else if (!strcasecmp( "TrashRemoteNew", cfg->cmd )) {
		store->trash_remote_new = parse_bool( cfg );
	} else if (!strcasecmp( "TrashNewOnly", cfg->cmd )) {
		store->trash_only_new = parse_bool( cfg );
	} else if (!strcasecmp( "MaxSize", cfg->cmd )) {
		store->max_size = parse_size( cfg );
	} else if (!strcasecmp( "MapInbox", cfg->cmd )) {
		store->map_inbox = nfstrdup( cfg->val );
	} else if (!strcasecmp( "Flatten", cfg->cmd )) {
		const char *p;
		for (p = cfg->val; *p; p++) {
			if (*p == '/') {
				error( "%s:%d: flattened hierarchy delimiter cannot contain the canonical delimiter '/'\n", cfg->file, cfg->line );
				cfg->err = 1;
				return;
			}
		}
		store->flat_delim = nfstrdup( cfg->val );
	} else {
		error( "%s:%d: unknown keyword '%s'\n", cfg->file, cfg->line, cfg->cmd );
		cfg->err = 1;
	}
}
