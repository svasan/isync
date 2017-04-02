/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2014 Oswald Buddenhagen <ossi@users.sf.net>
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

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Just to satisfy the references in util.c */
int DFlags;
const char *Home;

typedef struct {
	int id;
	int first, other, morph_at, morph_to;
	time_t start;
	wakeup_t timer;
	wakeup_t morph_timer;
} tst_t;

static void
timer_start( tst_t *timer, int to )
{
	printf( "starting timer %d, should expire after %d\n", timer->id, to );
	time( &timer->start );
	conf_wakeup( &timer->timer, to );
}

static void
timed_out( void *aux )
{
	tst_t *timer = (tst_t *)aux;

	printf( "timer %d expired after %d, repeat %d\n",
	        timer->id, (int)(time( 0 ) - timer->start), timer->other );
	if (timer->other >= 0) {
		timer_start( timer, timer->other );
	} else {
		wipe_wakeup( &timer->timer );
		wipe_wakeup( &timer->morph_timer );
		free( timer );
	}
}

static void
morph_timed_out( void *aux )
{
	tst_t *timer = (tst_t *)aux;

	printf( "morphing timer %d after %d\n",
	        timer->id, (int)(time( 0 ) - timer->start) );
	timer_start( timer, timer->morph_to );
}

static int nextid;

int
main( int argc, char **argv )
{
	int i;

	for (i = 1; i < argc; i++) {
		char *val = argv[i];
		tst_t *timer = nfmalloc( sizeof(*timer) );
		init_wakeup( &timer->timer, timed_out, timer );
		init_wakeup( &timer->morph_timer, morph_timed_out, timer );
		timer->id = ++nextid;
		timer->first = strtol( val, &val, 0 );
		if (*val == '@') {
			timer->other = timer->first;
			timer->first = strtol( ++val, &val, 0 );
		} else {
			timer->other = -1;
		}
		if (*val == ':') {
			timer->morph_to = strtol( ++val, &val, 0 );
			if (*val != '@')
				goto fail;
			timer->morph_at = strtol( ++val, &val, 0 );
		} else {
			timer->morph_at = -1;
		}
		if (*val) {
		  fail:
			fprintf( stderr, "Fatal: syntax error in %s, use <timeout>[@<delay>][:<newtimeout>@<delay>]\n", argv[i] );
			return 1;
		}
		timer_start( timer, timer->first );
		if (timer->morph_at >= 0) {
			printf( "timer %d, should morph after %d\n", timer->id, timer->morph_at );
			conf_wakeup( &timer->morph_timer, timer->morph_at );
		}
	}

	main_loop();
	return 0;
}
