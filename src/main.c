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

#include "sync.h"

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>

int DFlags;
int UseFSync = 1;

int Pid;		/* for maildir and imap */
char Hostname[256];	/* for maildir */
const char *Home;	/* for config */

static void
version( void )
{
	puts( PACKAGE " " VERSION );
	exit( 0 );
}

static void
usage( int code )
{
	fputs(
PACKAGE " " VERSION " - mailbox synchronizer\n"
"Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>\n"
"Copyright (C) 2002-2006,2008,2010-2012 Oswald Buddenhagen <ossi@users.sf.net>\n"
"Copyright (C) 2004 Theodore Ts'o <tytso@mit.edu>\n"
"usage:\n"
" " EXE " [flags] {{channel[:box,...]|group} ...|-a}\n"
"  -a, --all		operate on all defined channels\n"
"  -l, --list		list mailboxes instead of syncing them\n"
"  -n, --new		propagate new messages\n"
"  -d, --delete		propagate message deletions\n"
"  -f, --flags		propagate message flag changes\n"
"  -N, --renew		propagate previously not propagated new messages\n"
"  -L, --pull		propagate from master to slave\n"
"  -H, --push		propagate from slave to master\n"
"  -C, --create		create mailboxes if nonexistent\n"
"  -X, --expunge		expunge	deleted messages\n"
"  -c, --config CONFIG	read an alternate config file (default: ~/." EXE "rc)\n"
"  -D, --debug		print debugging messages\n"
"  -V, --verbose		verbose mode (display network traffic)\n"
"  -q, --quiet		don't display progress info\n"
"  -v, --version		display version\n"
"  -h, --help		display this help message\n"
"\nIf neither --pull nor --push are specified, both are active.\n"
"If neither --new, --delete, --flags nor --renew are specified, all are active.\n"
"Direction and operation can be concatenated like --pull-new, etc.\n"
"--create and --expunge can be suffixed with -master/-slave. Read the man page.\n"
"\nSupported mailbox formats are: IMAP4rev1, Maildir\n"
"\nCompile time options:\n"
#ifdef HAVE_LIBSSL
"  +HAVE_LIBSSL\n"
#else
"  -HAVE_LIBSSL\n"
#endif
	, code ? stderr : stdout );
	exit( code );
}

#ifdef __linux__
static void
crashHandler( int n )
{
	int dpid;
	char pbuf[10], pabuf[20];

	close( 0 );
	open( "/dev/tty", O_RDWR );
	dup2( 0, 1 );
	dup2( 0, 2 );
	error( "*** " EXE " caught signal %d. Starting debugger ...\n", n );
	switch ((dpid = fork())) {
	case -1:
		perror( "fork()" );
		break;
	case 0:
		sprintf( pbuf, "%d", Pid );
		sprintf( pabuf, "/proc/%d/exe", Pid );
		execlp( "gdb", "gdb", pabuf, pbuf, (char *)0 );
		perror( "execlp()" );
		_exit( 1 );
	default:
		waitpid( dpid, 0, 0 );
		break;
	}
	exit( 3 );
}
#endif

static int
matches( const char *t, const char *p )
{
	for (;;) {
		if (!*p)
			return !*t;
		if (*p == '*') {
			p++;
			do {
				if (matches( t, p ))
					return 1;
			} while (*t++);
			return 0;
		} else if (*p == '%') {
			p++;
			do {
				if (*t == '/')
					return 0;
				if (matches( t, p ))
					return 1;
			} while (*t++);
			return 0;
		} else {
			if (*p != *t)
				return 0;
			p++, t++;
		}
	}
}

static string_list_t *
filter_boxes( string_list_t *boxes, const char *prefix, string_list_t *patterns )
{
	string_list_t *nboxes = 0, *cpat;
	const char *ps;
	int not, fnot, pfxl;

	pfxl = prefix ? strlen( prefix ) : 0;
	for (; boxes; boxes = boxes->next) {
		if (!starts_with( boxes->string, -1, prefix, pfxl ))
			continue;
		fnot = 1;
		for (cpat = patterns; cpat; cpat = cpat->next) {
			ps = cpat->string;
			if (*ps == '!') {
				ps++;
				not = 1;
			} else
				not = 0;
			if (matches( boxes->string + pfxl, ps )) {
				fnot = not;
				break;
			}
		}
		if (!fnot)
			add_string_list( &nboxes, boxes->string + pfxl );
	}
	return nboxes;
}

static void
merge_actions( channel_conf_t *chan, int ops[], int have, int mask, int def )
{
	if (ops[M] & have) {
		chan->ops[M] &= ~mask;
		chan->ops[M] |= ops[M] & mask;
		chan->ops[S] &= ~mask;
		chan->ops[S] |= ops[S] & mask;
	} else if (!(chan->ops[M] & have)) {
		if (global_conf.ops[M] & have) {
			chan->ops[M] |= global_conf.ops[M] & mask;
			chan->ops[S] |= global_conf.ops[S] & mask;
		} else {
			chan->ops[M] |= def;
			chan->ops[S] |= def;
		}
	}
}

typedef struct {
	int t[2];
	channel_conf_t *chan;
	driver_t *drv[2];
	store_t *ctx[2];
	string_list_t *boxes[2], *cboxes, *chanptr;
	char *names[2];
	char **argv;
	int oind, ret, multiple, all, list, ops[2], state[2];
	char done, skip, cben, boxlist;
} main_vars_t;

#define AUX &mvars->t[t]
#define MVARS(aux) \
	int t = *(int *)aux; \
	main_vars_t *mvars = (main_vars_t *)(((char *)(&((int *)aux)[-t])) - offsetof(main_vars_t, t));

#define E_START  0
#define E_OPEN   1
#define E_SYNC   2

static void sync_chans( main_vars_t *mvars, int ent );

int
main( int argc, char **argv )
{
	main_vars_t mvars[1];
	group_conf_t *group;
	char *config = 0, *opt, *ochar;
	int cops = 0, op, pseudo = 0;

	tzset();
	gethostname( Hostname, sizeof(Hostname) );
	if ((ochar = strchr( Hostname, '.' )))
		*ochar = 0;
	Pid = getpid();
	if (!(Home = getenv("HOME"))) {
		fputs( "Fatal: $HOME not set\n", stderr );
		return 1;
	}
	arc4_init();

	memset( mvars, 0, sizeof(*mvars) );
	mvars->t[1] = 1;

	for (mvars->oind = 1, ochar = 0; ; ) {
		if (!ochar || !*ochar) {
			if (mvars->oind >= argc)
				break;
			if (argv[mvars->oind][0] != '-')
				break;
			if (argv[mvars->oind][1] == '-') {
				opt = argv[mvars->oind++] + 2;
				if (!*opt)
					break;
				if (!strcmp( opt, "config" )) {
					if (mvars->oind >= argc) {
						error( "--config requires an argument.\n" );
						return 1;
					}
					config = argv[mvars->oind++];
				} else if (starts_with( opt, -1, "config=", 7 ))
					config = opt + 7;
				else if (!strcmp( opt, "all" ))
					mvars->all = 1;
				else if (!strcmp( opt, "list" ))
					mvars->list = 1;
				else if (!strcmp( opt, "help" ))
					usage( 0 );
				else if (!strcmp( opt, "version" ))
					version();
				else if (!strcmp( opt, "quiet" )) {
					if (DFlags & QUIET)
						DFlags |= VERYQUIET;
					else
						DFlags |= QUIET;
				} else if (!strcmp( opt, "verbose" )) {
					if (DFlags & VERBOSE)
						DFlags |= XVERBOSE;
					else
						DFlags |= VERBOSE | QUIET;
				} else if (!strcmp( opt, "debug" ))
					DFlags |= DEBUG | QUIET;
				else if (!strcmp( opt, "pull" ))
					cops |= XOP_PULL, mvars->ops[M] |= XOP_HAVE_TYPE;
				else if (!strcmp( opt, "push" ))
					cops |= XOP_PUSH, mvars->ops[M] |= XOP_HAVE_TYPE;
				else if (starts_with( opt, -1, "create", 6 )) {
					opt += 6;
					op = OP_CREATE|XOP_HAVE_CREATE;
				  lcop:
					if (!*opt)
						cops |= op;
					else if (!strcmp( opt, "-master" ))
						mvars->ops[M] |= op;
					else if (!strcmp( opt, "-slave" ))
						mvars->ops[S] |= op;
					else
						goto badopt;
					mvars->ops[M] |= op & (XOP_HAVE_CREATE|XOP_HAVE_EXPUNGE);
				} else if (starts_with( opt, -1, "expunge", 7 )) {
					opt += 7;
					op = OP_EXPUNGE|XOP_HAVE_EXPUNGE;
					goto lcop;
				} else if (!strcmp( opt, "no-expunge" ))
					mvars->ops[M] |= XOP_HAVE_EXPUNGE;
				else if (!strcmp( opt, "no-create" ))
					mvars->ops[M] |= XOP_HAVE_CREATE;
				else if (!strcmp( opt, "full" ))
					mvars->ops[M] |= XOP_HAVE_TYPE|XOP_PULL|XOP_PUSH;
				else if (!strcmp( opt, "noop" ))
					mvars->ops[M] |= XOP_HAVE_TYPE;
				else if (starts_with( opt, -1, "pull", 4 )) {
					op = XOP_PULL;
				  lcac:
					opt += 4;
					if (!*opt)
						cops |= op;
					else if (*opt == '-') {
						opt++;
						goto rlcac;
					} else
						goto badopt;
				} else if (starts_with( opt, -1, "push", 4 )) {
					op = XOP_PUSH;
					goto lcac;
				} else {
					op = 0;
				  rlcac:
					if (!strcmp( opt, "new" ))
						op |= OP_NEW;
					else if (!strcmp( opt, "renew" ))
						op |= OP_RENEW;
					else if (!strcmp( opt, "delete" ))
						op |= OP_DELETE;
					else if (!strcmp( opt, "flags" ))
						op |= OP_FLAGS;
					else {
					  badopt:
						error( "Unknown option '%s'\n", argv[mvars->oind - 1] );
						return 1;
					}
					switch (op & XOP_MASK_DIR) {
					case XOP_PULL: mvars->ops[S] |= op & OP_MASK_TYPE; break;
					case XOP_PUSH: mvars->ops[M] |= op & OP_MASK_TYPE; break;
					default: cops |= op; break;
					}
					mvars->ops[M] |= XOP_HAVE_TYPE;
				}
				continue;
			}
			ochar = argv[mvars->oind++] + 1;
			if (!*ochar) {
				error( "Invalid option '-'\n" );
				return 1;
			}
		}
		switch (*ochar++) {
		case 'a':
			mvars->all = 1;
			break;
		case 'l':
			mvars->list = 1;
			break;
		case 'c':
			if (*ochar == 'T') {
				ochar++;
				pseudo = 1;
			}
			if (mvars->oind >= argc) {
				error( "-c requires an argument.\n" );
				return 1;
			}
			config = argv[mvars->oind++];
			break;
		case 'C':
			op = OP_CREATE|XOP_HAVE_CREATE;
		  cop:
			if (*ochar == 'm')
				mvars->ops[M] |= op, ochar++;
			else if (*ochar == 's')
				mvars->ops[S] |= op, ochar++;
			else if (*ochar == '-')
				ochar++;
			else
				cops |= op;
			mvars->ops[M] |= op & (XOP_HAVE_CREATE|XOP_HAVE_EXPUNGE);
			break;
		case 'X':
			op = OP_EXPUNGE|XOP_HAVE_EXPUNGE;
			goto cop;
		case 'F':
			cops |= XOP_PULL|XOP_PUSH;
			/* fallthrough */
		case '0':
			mvars->ops[M] |= XOP_HAVE_TYPE;
			break;
		case 'n':
		case 'd':
		case 'f':
		case 'N':
			--ochar;
			op = 0;
		  cac:
			for (;; ochar++) {
				if (*ochar == 'n')
					op |= OP_NEW;
				else if (*ochar == 'd')
					op |= OP_DELETE;
				else if (*ochar == 'f')
					op |= OP_FLAGS;
				else if (*ochar == 'N')
					op |= OP_RENEW;
				else
					break;
			}
			if (op & OP_MASK_TYPE)
				switch (op & XOP_MASK_DIR) {
				case XOP_PULL: mvars->ops[S] |= op & OP_MASK_TYPE; break;
				case XOP_PUSH: mvars->ops[M] |= op & OP_MASK_TYPE; break;
				default: cops |= op; break;
				}
			else
				cops |= op;
			mvars->ops[M] |= XOP_HAVE_TYPE;
			break;
		case 'L':
			op = XOP_PULL;
			goto cac;
		case 'H':
			op = XOP_PUSH;
			goto cac;
		case 'q':
			if (DFlags & QUIET)
				DFlags |= VERYQUIET;
			else
				DFlags |= QUIET;
			break;
		case 'V':
			if (DFlags & VERBOSE)
				DFlags |= XVERBOSE;
			else
				DFlags |= VERBOSE | QUIET;
			break;
		case 'D':
			if (*ochar == 'C')
				DFlags |= CRASHDEBUG, ochar++;
			else
				DFlags |= CRASHDEBUG | DEBUG | QUIET;
			break;
		case 'J':
			DFlags |= KEEPJOURNAL;
			break;
		case 'Z':
			DFlags |= ZERODELAY;
			break;
		case 'v':
			version();
		case 'h':
			usage( 0 );
		default:
			error( "Unknown option '-%c'\n", *(ochar - 1) );
			return 1;
		}
	}

#ifdef __linux__
	if (DFlags & CRASHDEBUG) {
		signal( SIGSEGV, crashHandler );
		signal( SIGBUS, crashHandler );
		signal( SIGILL, crashHandler );
	}
#endif

	if (merge_ops( cops, mvars->ops ))
		return 1;

	if (load_config( config, pseudo ))
		return 1;

	if (!mvars->all && !argv[mvars->oind]) {
		fputs( "No channel specified. Try '" EXE " -h'\n", stderr );
		return 1;
	}
	if (!channels) {
		fputs( "No channels defined. Try 'man " EXE "'\n", stderr );
		return 1;
	}

	mvars->chan = channels;
	if (mvars->all)
		mvars->multiple = channels->next != 0;
	else if (argv[mvars->oind + 1])
		mvars->multiple = 1;
	else
		for (group = groups; group; group = group->next)
			if (!strcmp( group->name, argv[mvars->oind] )) {
				mvars->multiple = 1;
				break;
			}
	mvars->argv = argv;
	mvars->cben = 1;
	sync_chans( mvars, E_START );
	main_loop();
	return mvars->ret;
}

#define ST_FRESH     0
#define ST_OPEN      1
#define ST_CLOSED    2

static void store_opened( store_t *ctx, void *aux );
static void store_listed( int sts, void *aux );
static int sync_listed_boxes( main_vars_t *mvars, string_list_t *mbox );
static void done_sync_dyn( int sts, void *aux );
static void done_sync_2_dyn( int sts, void *aux );
static void done_sync( int sts, void *aux );

#define nz(a,b) ((a)?(a):(b))

static void
sync_chans( main_vars_t *mvars, int ent )
{
	group_conf_t *group;
	channel_conf_t *chan;
	string_list_t *mbox, *sbox, **mboxp, **sboxp;
	char *channame, *boxp, *nboxp;
	const char *labels[2];
	int t;

	if (!mvars->cben)
		return;
	switch (ent) {
	case E_OPEN: goto opened;
	case E_SYNC: goto syncone;
	}
	for (;;) {
		mvars->boxlist = 0;
		mvars->boxes[M] = mvars->boxes[S] = mvars->cboxes = 0;
		if (!mvars->all) {
			if (mvars->chanptr)
				channame = mvars->chanptr->string;
			else {
				for (group = groups; group; group = group->next)
					if (!strcmp( group->name, mvars->argv[mvars->oind] )) {
						mvars->chanptr = group->channels;
						channame = mvars->chanptr->string;
						goto gotgrp;
					}
				channame = mvars->argv[mvars->oind];
			  gotgrp: ;
			}
			if ((boxp = strchr( channame, ':' )))
				*boxp++ = 0;
			for (chan = channels; chan; chan = chan->next)
				if (!strcmp( chan->name, channame ))
					goto gotchan;
			error( "No channel or group named '%s' defined.\n", channame );
			mvars->ret = 1;
			goto gotnone;
		  gotchan:
			mvars->chan = chan;
			if (boxp) {
				if (!chan->patterns) {
					error( "Cannot override mailbox in channel '%s' - no Patterns.\n", channame );
					mvars->ret = 1;
					goto gotnone;
				}
				mvars->boxlist = 1;
				for (;;) {
					nboxp = strpbrk( boxp, ",\n" );
					if (nboxp) {
						t = nboxp - boxp;
						*nboxp++ = 0;
					} else {
						t = strlen( boxp );
					}
					if (t)
						add_string_list_n( &mvars->cboxes, boxp, t );
					else
						add_string_list_n( &mvars->cboxes, "INBOX", 5 );
					if (!nboxp)
						break;
					boxp = nboxp;
				}
			}
		}
		merge_actions( mvars->chan, mvars->ops, XOP_HAVE_TYPE, OP_MASK_TYPE, OP_MASK_TYPE );
		merge_actions( mvars->chan, mvars->ops, XOP_HAVE_CREATE, OP_CREATE, 0 );
		merge_actions( mvars->chan, mvars->ops, XOP_HAVE_EXPUNGE, OP_EXPUNGE, 0 );

		mvars->state[M] = mvars->state[S] = ST_FRESH;
		info( "Channel %s\n", mvars->chan->name );
		mvars->skip = mvars->cben = 0;
		if (mvars->chan->stores[M]->driver->flags & mvars->chan->stores[S]->driver->flags & DRV_VERBOSE)
			labels[M] = "M: ", labels[S] = "S: ";
		else
			labels[M] = labels[S] = "";
		for (t = 0; ; t++) {
			info( "Opening %s %s...\n", str_ms[t], mvars->chan->stores[t]->name );
			mvars->drv[t] = mvars->chan->stores[t]->driver;
			mvars->drv[t]->open_store( mvars->chan->stores[t], labels[t], store_opened, AUX );
			if (t)
				break;
			if (mvars->skip) {
				mvars->state[1] = ST_CLOSED;
				break;
			}
		}
		mvars->cben = 1;
	  opened:
		if (mvars->skip)
			goto next;
		if (mvars->state[M] != ST_OPEN || mvars->state[S] != ST_OPEN)
			return;

		if (!mvars->boxlist && mvars->chan->patterns) {
			mvars->boxlist = 1;
			mvars->boxes[M] = filter_boxes( mvars->ctx[M]->boxes, mvars->chan->boxes[M], mvars->chan->patterns );
			mvars->boxes[S] = filter_boxes( mvars->ctx[S]->boxes, mvars->chan->boxes[S], mvars->chan->patterns );
			for (mboxp = &mvars->boxes[M]; (mbox = *mboxp); ) {
				for (sboxp = &mvars->boxes[S]; (sbox = *sboxp); sboxp = &sbox->next)
					if (!strcmp( sbox->string, mbox->string )) {
						*sboxp = sbox->next;
						free( sbox );
						*mboxp = mbox->next;
						mbox->next = mvars->cboxes;
						mvars->cboxes = mbox;
						goto gotdupe;
					}
				mboxp = &mbox->next;
			  gotdupe: ;
			}
		}

		if (mvars->list && mvars->multiple)
			printf( "%s:\n", mvars->chan->name );
	  syncml:
		mvars->done = mvars->cben = 0;
		if (mvars->boxlist) {
			while ((mbox = mvars->cboxes)) {
				mvars->cboxes = mbox->next;
				if (sync_listed_boxes( mvars, mbox ))
					goto syncw;
			}
			for (t = 0; t < 2; t++)
				while ((mbox = mvars->boxes[t])) {
					mvars->boxes[t] = mbox->next;
					if ((mvars->chan->ops[1-t] & OP_MASK_TYPE) && (mvars->chan->ops[1-t] & OP_CREATE)) {
						if (sync_listed_boxes( mvars, mbox ))
							goto syncw;
					} else {
						free( mbox );
					}
				}
		} else {
			if (!mvars->list) {
				sync_boxes( mvars->ctx, mvars->chan->boxes, mvars->chan, done_sync, mvars );
				mvars->skip = 1;
			  syncw:
				mvars->cben = 1;
				if (!mvars->done)
					return;
			  syncone:
				if (!mvars->skip)
					goto syncml;
			} else
				printf( "%s <=> %s\n", nz( mvars->chan->boxes[M], "INBOX" ), nz( mvars->chan->boxes[S], "INBOX" ) );
		}

	  next:
		for (t = 0; t < 2; t++)
			if (mvars->state[t] == ST_OPEN) {
				mvars->drv[t]->disown_store( mvars->ctx[t] );
				mvars->state[t] = ST_CLOSED;
			}
		if (mvars->state[M] != ST_CLOSED || mvars->state[S] != ST_CLOSED) {
			mvars->skip = mvars->cben = 1;
			return;
		}
		free_string_list( mvars->cboxes );
		free_string_list( mvars->boxes[M] );
		free_string_list( mvars->boxes[S] );
		if (mvars->all) {
			if (!(mvars->chan = mvars->chan->next))
				break;
		} else {
			if (mvars->chanptr && (mvars->chanptr = mvars->chanptr->next))
				continue;
		  gotnone:
			if (!mvars->argv[++mvars->oind])
				break;
		}
	}
	for (t = 0; t < N_DRIVERS; t++)
		drivers[t]->cleanup();
}

static void
store_bad( void *aux )
{
	MVARS(aux)

	mvars->drv[t]->cancel_store( mvars->ctx[t] );
	mvars->ret = mvars->skip = 1;
	mvars->state[t] = ST_CLOSED;
	sync_chans( mvars, E_OPEN );
}

static void
store_opened( store_t *ctx, void *aux )
{
	MVARS(aux)
	string_list_t *cpat;
	int flags;

	if (!ctx) {
		mvars->ret = mvars->skip = 1;
		mvars->state[t] = ST_CLOSED;
		sync_chans( mvars, E_OPEN );
		return;
	}
	mvars->ctx[t] = ctx;
	if (!mvars->skip && !mvars->boxlist && mvars->chan->patterns && !ctx->listed) {
		for (flags = 0, cpat = mvars->chan->patterns; cpat; cpat = cpat->next) {
			const char *pat = cpat->string;
			if (*pat != '!') {
				char buf[8];
				int bufl = snprintf( buf, sizeof(buf), "%s%s", mvars->chan->boxes[t], pat );
				/* Partial matches like "INB*" or even "*" are not considered,
				 * except implicity when the INBOX lives under Path. */
				if (starts_with( buf, bufl, "INBOX", 5 )) {
					char c = buf[5];
					if (!c) {
						/* User really wants the INBOX. */
						flags |= LIST_INBOX;
					} else if (c == '/') {
						/* Flattened sub-folders of INBOX actually end up in Path. */
						if (ctx->conf->flat_delim)
							flags |= LIST_PATH;
						else
							flags |= LIST_INBOX;
					} else {
						/* User may not want the INBOX after all ... */
						flags |= LIST_PATH;
						/* ... but maybe he does.
						 * The flattened sub-folder case is implicitly covered by the previous line. */
						if (c == '*' || c == '%')
							flags |= LIST_INBOX;
					}
				} else {
					flags |= LIST_PATH;
				}
			}
		}
		set_bad_callback( ctx, store_bad, AUX );
		mvars->drv[t]->list( ctx, flags, store_listed, AUX );
	} else {
		mvars->state[t] = ST_OPEN;
		sync_chans( mvars, E_OPEN );
	}
}

static void
store_listed( int sts, void *aux )
{
	MVARS(aux)
	string_list_t **box;

	switch (sts) {
	case DRV_CANCELED:
		return;
	case DRV_OK:
		mvars->ctx[t]->listed = 1;
		if (mvars->ctx[t]->conf->flat_delim) {
			for (box = &mvars->ctx[t]->boxes; *box; box = &(*box)->next) {
				string_list_t *nbox;
				if (map_name( (*box)->string, (char **)&nbox, offsetof(string_list_t, string), mvars->ctx[t]->conf->flat_delim, "/" ) < 0) {
					error( "Error: flattened mailbox name '%s' contains canonical hierarchy delimiter\n", (*box)->string );
					mvars->ret = mvars->skip = 1;
				} else {
					nbox->next = (*box)->next;
					free( *box );
					*box = nbox;
				}
			}
		}
		if (mvars->ctx[t]->conf->map_inbox)
			add_string_list( &mvars->ctx[t]->boxes, mvars->ctx[t]->conf->map_inbox );
		break;
	default:
		mvars->ret = mvars->skip = 1;
		break;
	}
	mvars->state[t] = ST_OPEN;
	sync_chans( mvars, E_OPEN );
}

static int
sync_listed_boxes( main_vars_t *mvars, string_list_t *mbox )
{
	if (mvars->chan->boxes[M] || mvars->chan->boxes[S]) {
		const char *mpfx = nz( mvars->chan->boxes[M], "" );
		const char *spfx = nz( mvars->chan->boxes[S], "" );
		if (!mvars->list) {
			nfasprintf( &mvars->names[M], "%s%s", mpfx, mbox->string );
			nfasprintf( &mvars->names[S], "%s%s", spfx, mbox->string );
			free( mbox );
			sync_boxes( mvars->ctx, (const char **)mvars->names, mvars->chan, done_sync_2_dyn, mvars );
			return 1;
		}
		printf( "%s%s <=> %s%s\n", mpfx, mbox->string, spfx, mbox->string );
	} else {
		if (!mvars->list) {
			mvars->names[M] = mvars->names[S] = mbox->string;
			sync_boxes( mvars->ctx, (const char **)mvars->names, mvars->chan, done_sync_dyn, mvars );
			return 1;
		}
		puts( mbox->string );
	}
	free( mbox );
	return 0;
}

static void
done_sync_dyn( int sts, void *aux )
{
	main_vars_t *mvars = (main_vars_t *)aux;

	free( ((char *)mvars->names[S]) - offsetof(string_list_t, string) );
	done_sync( sts, aux );
}

static void
done_sync_2_dyn( int sts, void *aux )
{
	main_vars_t *mvars = (main_vars_t *)aux;

	free( mvars->names[M] );
	free( mvars->names[S] );
	done_sync( sts, aux );
}

static void
done_sync( int sts, void *aux )
{
	main_vars_t *mvars = (main_vars_t *)aux;

	mvars->done = 1;
	if (sts) {
		mvars->ret = 1;
		if (sts & (SYNC_BAD(M) | SYNC_BAD(S))) {
			if (sts & SYNC_BAD(M))
				mvars->state[M] = ST_CLOSED;
			if (sts & SYNC_BAD(S))
				mvars->state[S] = ST_CLOSED;
			mvars->skip = 1;
		} else if (sts & SYNC_FAIL_ALL) {
			mvars->skip = 1;
		}
	}
	sync_chans( mvars, E_SYNC );
}
