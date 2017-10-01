/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2010-2017 Oswald Buddenhagen <ossi@users.sf.net>
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
int JLimit;
int UseFSync = 1;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__) || defined(__CYGWIN__)
char FieldDelimiter = ';';
#else
char FieldDelimiter = ':';
#endif

int Pid;		/* for maildir and imap */
char Hostname[256];	/* for maildir */
const char *Home;	/* for config */

int BufferLimit = 10 * 1024 * 1024;

int chans_total, chans_done;
int boxes_total, boxes_done;
int new_total[2], new_done[2];
int flags_total[2], flags_done[2];
int trash_total[2], trash_done[2];

static void ATTR_NORETURN
version( void )
{
	puts( PACKAGE " " VERSION );
	exit( 0 );
}

static void ATTR_NORETURN
usage( int code )
{
	fputs(
PACKAGE " " VERSION " - mailbox synchronizer\n"
"Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>\n"
"Copyright (C) 2002-2006,2008,2010-2017 Oswald Buddenhagen <ossi@users.sf.net>\n"
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
"  -D, --debug		debugging modes (see manual)\n"
"  -V, --verbose		display what is happening\n"
"  -q, --quiet		don't display progress counters\n"
"  -v, --version		display version\n"
"  -h, --help		display this help message\n"
"\nIf neither --pull nor --push are specified, both are active.\n"
"If neither --new, --delete, --flags nor --renew are specified, all are active.\n"
"Direction and operation can be concatenated like --pull-new, etc.\n"
"--create and --expunge can be suffixed with -master/-slave. Read the man page.\n"
"\nSupported mailbox formats are: IMAP4rev1, Maildir\n"
"\nCompile time options:\n"
#ifdef HAVE_LIBSSL
"  +HAVE_LIBSSL"
#else
"  -HAVE_LIBSSL"
#endif
#ifdef HAVE_LIBSASL
" +HAVE_LIBSASL"
#else
" -HAVE_LIBSASL"
#endif
#ifdef HAVE_LIBZ
" +HAVE_LIBZ"
#else
" -HAVE_LIBZ"
#endif
#ifdef USE_DB
" +USE_DB"
#else
" -USE_DB"
#endif
#ifdef HAVE_IPV6
" +HAVE_IPV6\n"
#else
" -HAVE_IPV6\n"
#endif
	, code ? stderr : stdout );
	exit( code );
}

static void ATTR_PRINTFLIKE(1, 2)
debug( const char *msg, ... )
{
	va_list va;

	va_start( va, msg );
	vdebug( DEBUG_MAIN, msg, va );
	va_end( va );
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

void
stats( void )
{
	char buf[3][64];
	char *cs;
	int t, l, ll, cls;
	static int cols = -1;

	if (!(DFlags & PROGRESS))
		return;

	if (cols < 0 && (!(cs = getenv( "COLUMNS" )) || !(cols = atoi( cs ))))
		cols = 80;
	ll = sprintf( buf[2], "C: %d/%d  B: %d/%d", chans_done, chans_total, boxes_done, boxes_total );
	cls = (cols - ll - 10) / 2;
	for (t = 0; t < 2; t++) {
		l = sprintf( buf[t], "+%d/%d *%d/%d #%d/%d",
		             new_done[t], new_total[t],
		             flags_done[t], flags_total[t],
		             trash_done[t], trash_total[t] );
		if (l > cls)
			buf[t][cls - 1] = '~';
	}
	progress( "\r%s  M: %.*s  S: %.*s", buf[2], cls, buf[0], cls, buf[1] );
}

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


static int
is_inbox( const char *name )
{
	return starts_with( name, -1, "INBOX", 5 ) && (!name[5] || name[5] == '/');
}

static int
cmp_box_names( const void *a, const void *b )
{
	const char *as = *(const char **)a;
	const char *bs = *(const char **)b;
	int ai = is_inbox( as );
	int bi = is_inbox( bs );
	int di = bi - ai;
	if (di)
		return di;
	return strcmp( as, bs );
}

static char **
filter_boxes( string_list_t *boxes, const char *prefix, string_list_t *patterns )
{
	string_list_t *cpat;
	char **boxarr = 0;
	const char *ps;
	int not, fnot, pfxl, num = 0, rnum = 0;

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
		if (!fnot) {
			if (num + 1 >= rnum)
				boxarr = nfrealloc( boxarr, (rnum = (rnum + 10) * 2) * sizeof(*boxarr) );
			boxarr[num++] = nfstrdup( boxes->string + pfxl );
			boxarr[num] = 0;
		}
	}
	qsort( boxarr, num, sizeof(*boxarr), cmp_box_names );
	return boxarr;
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

typedef struct box_ent {
	struct box_ent *next;
	char *name;
	int present[2];
} box_ent_t;

typedef struct chan_ent {
	struct chan_ent *next;
	channel_conf_t *conf;
	box_ent_t *boxes;
	char boxlist;
} chan_ent_t;

static chan_ent_t *
add_channel( chan_ent_t ***chanapp, channel_conf_t *chan, int ops[] )
{
	chan_ent_t *ce = nfcalloc( sizeof(*ce) );
	ce->conf = chan;

	merge_actions( chan, ops, XOP_HAVE_TYPE, OP_MASK_TYPE, OP_MASK_TYPE );
	merge_actions( chan, ops, XOP_HAVE_CREATE, OP_CREATE, 0 );
	merge_actions( chan, ops, XOP_HAVE_REMOVE, OP_REMOVE, 0 );
	merge_actions( chan, ops, XOP_HAVE_EXPUNGE, OP_EXPUNGE, 0 );

	**chanapp = ce;
	*chanapp = &ce->next;
	chans_total++;
	return ce;
}

static chan_ent_t *
add_named_channel( chan_ent_t ***chanapp, char *channame, int ops[] )
{
	channel_conf_t *chan;
	chan_ent_t *ce;
	box_ent_t *boxes = 0, **mboxapp = &boxes, *mbox;
	char *boxp, *nboxp;
	int boxl, boxlist = 0;

	if ((boxp = strchr( channame, ':' )))
		*boxp++ = 0;
	for (chan = channels; chan; chan = chan->next)
		if (!strcmp( chan->name, channame ))
			goto gotchan;
	error( "No channel or group named '%s' defined.\n", channame );
	return 0;
  gotchan:
	if (boxp) {
		if (!chan->patterns) {
			error( "Cannot override mailbox in channel '%s' - no Patterns.\n", channame );
			return 0;
		}
		boxlist = 1;
		do {
			nboxp = strpbrk( boxp, ",\n" );
			if (nboxp) {
				boxl = nboxp - boxp;
				*nboxp++ = 0;
			} else {
				boxl = strlen( boxp );
			}
			mbox = nfmalloc( sizeof(*mbox) );
			if (boxl)
				mbox->name = nfstrndup( boxp, boxl );
			else
				mbox->name = nfstrndup( "INBOX", 5 );
			mbox->present[M] = mbox->present[S] = BOX_POSSIBLE;
			mbox->next = 0;
			*mboxapp = mbox;
			mboxapp = &mbox->next;
			boxes_total++;
			boxp = nboxp;
		} while (boxp);
	} else {
		if (!chan->patterns)
			boxes_total++;
	}

	ce = add_channel( chanapp, chan, ops );
	ce->boxes = boxes;
	ce->boxlist = boxlist;
	return ce;
}

typedef struct {
	int t[2];
	channel_conf_t *chan;
	driver_t *drv[2];
	store_t *ctx[2];
	chan_ent_t *chanptr;
	box_ent_t *boxptr;
	string_list_t *boxes[2];
	char *names[2];
	int ret, all, list, state[2];
	char done, skip, cben;
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
	chan_ent_t *chans = 0, **chanapp = &chans;
	group_conf_t *group;
	channel_conf_t *chan;
	string_list_t *channame;
	char *config = 0, *opt, *ochar;
	int oind, cops = 0, op, ops[2] = { 0, 0 }, pseudo = 0;

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

	for (oind = 1, ochar = 0; ; ) {
		if (!ochar || !*ochar) {
			if (oind >= argc)
				break;
			if (argv[oind][0] != '-')
				break;
			if (argv[oind][1] == '-') {
				opt = argv[oind++] + 2;
				if (!*opt)
					break;
				if (!strcmp( opt, "config" )) {
					if (oind >= argc) {
						error( "--config requires an argument.\n" );
						return 1;
					}
					config = argv[oind++];
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
					DFlags |= VERBOSE;
				} else if (starts_with( opt, -1, "debug", 5 )) {
					opt += 5;
					if (!*opt)
						op = VERBOSE | DEBUG_ALL;
					else if (!strcmp( opt, "-crash" ))
						op = DEBUG_CRASH;
					else if (!strcmp( opt, "-driver" ))
						op = VERBOSE | DEBUG_DRV;
					else if (!strcmp( opt, "-driver-all" ))
						op = VERBOSE | DEBUG_DRV | DEBUG_DRV_ALL;
					else if (!strcmp( opt, "-maildir" ))
						op = VERBOSE | DEBUG_MAILDIR;
					else if (!strcmp( opt, "-main" ))
						op = VERBOSE | DEBUG_MAIN;
					else if (!strcmp( opt, "-net" ))
						op = VERBOSE | DEBUG_NET;
					else if (!strcmp( opt, "-net-all" ))
						op = VERBOSE | DEBUG_NET | DEBUG_NET_ALL;
					else if (!strcmp( opt, "-sync" ))
						op = VERBOSE | DEBUG_SYNC;
					else
						goto badopt;
					DFlags |= op;
				} else if (!strcmp( opt, "pull" ))
					cops |= XOP_PULL, ops[M] |= XOP_HAVE_TYPE;
				else if (!strcmp( opt, "push" ))
					cops |= XOP_PUSH, ops[M] |= XOP_HAVE_TYPE;
				else if (starts_with( opt, -1, "create", 6 )) {
					opt += 6;
					op = OP_CREATE|XOP_HAVE_CREATE;
				  lcop:
					if (!*opt)
						cops |= op;
					else if (!strcmp( opt, "-master" ))
						ops[M] |= op;
					else if (!strcmp( opt, "-slave" ))
						ops[S] |= op;
					else
						goto badopt;
					ops[M] |= op & (XOP_HAVE_CREATE|XOP_HAVE_REMOVE|XOP_HAVE_EXPUNGE);
				} else if (starts_with( opt, -1, "remove", 6 )) {
					opt += 6;
					op = OP_REMOVE|XOP_HAVE_REMOVE;
					goto lcop;
				} else if (starts_with( opt, -1, "expunge", 7 )) {
					opt += 7;
					op = OP_EXPUNGE|XOP_HAVE_EXPUNGE;
					goto lcop;
				} else if (!strcmp( opt, "no-expunge" ))
					ops[M] |= XOP_HAVE_EXPUNGE;
				else if (!strcmp( opt, "no-create" ))
					ops[M] |= XOP_HAVE_CREATE;
				else if (!strcmp( opt, "no-remove" ))
					ops[M] |= XOP_HAVE_REMOVE;
				else if (!strcmp( opt, "full" ))
					ops[M] |= XOP_HAVE_TYPE|XOP_PULL|XOP_PUSH;
				else if (!strcmp( opt, "noop" ))
					ops[M] |= XOP_HAVE_TYPE;
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
						error( "Unknown option '%s'\n", argv[oind - 1] );
						return 1;
					}
					switch (op & XOP_MASK_DIR) {
					case XOP_PULL: ops[S] |= op & OP_MASK_TYPE; break;
					case XOP_PUSH: ops[M] |= op & OP_MASK_TYPE; break;
					default: cops |= op; break;
					}
					ops[M] |= XOP_HAVE_TYPE;
				}
				continue;
			}
			ochar = argv[oind++] + 1;
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
			if (oind >= argc) {
				error( "-c requires an argument.\n" );
				return 1;
			}
			config = argv[oind++];
			break;
		case 'C':
			op = OP_CREATE|XOP_HAVE_CREATE;
		  cop:
			if (*ochar == 'm')
				ops[M] |= op, ochar++;
			else if (*ochar == 's')
				ops[S] |= op, ochar++;
			else if (*ochar == '-')
				ochar++;
			else
				cops |= op;
			ops[M] |= op & (XOP_HAVE_CREATE|XOP_HAVE_REMOVE|XOP_HAVE_EXPUNGE);
			break;
		case 'R':
			op = OP_REMOVE|XOP_HAVE_REMOVE;
			goto cop;
		case 'X':
			op = OP_EXPUNGE|XOP_HAVE_EXPUNGE;
			goto cop;
		case 'F':
			cops |= XOP_PULL|XOP_PUSH;
			FALLTHROUGH
		case '0':
			ops[M] |= XOP_HAVE_TYPE;
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
				case XOP_PULL: ops[S] |= op & OP_MASK_TYPE; break;
				case XOP_PUSH: ops[M] |= op & OP_MASK_TYPE; break;
				default: cops |= op; break;
				}
			else
				cops |= op;
			ops[M] |= XOP_HAVE_TYPE;
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
			DFlags |= VERBOSE;
			break;
		case 'D':
			for (op = 0; *ochar; ochar++) {
				switch (*ochar) {
				case 'C':
					op |= DEBUG_CRASH;
					break;
				case 'd':
					op |= DEBUG_DRV | VERBOSE;
					break;
				case 'D':
					op |= DEBUG_DRV | DEBUG_DRV_ALL | VERBOSE;
					break;
				case 'm':
					op |= DEBUG_MAILDIR | VERBOSE;
					break;
				case 'M':
					op |= DEBUG_MAIN | VERBOSE;
					break;
				case 'n':
					op |= DEBUG_NET | VERBOSE;
					break;
				case 'N':
					op |= DEBUG_NET | DEBUG_NET_ALL | VERBOSE;
					break;
				case 's':
					op |= DEBUG_SYNC | VERBOSE;
					break;
				default:
					error( "Unknown -D flag '%c'\n", *ochar );
					return 1;
				}
			}
			if (!op)
				op = DEBUG_ALL | VERBOSE;
			DFlags |= op;
			break;
		case 'J':
			DFlags |= KEEPJOURNAL;
			JLimit = strtol( ochar, &ochar, 10 );
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

	if (!(DFlags & (QUIET | DEBUG_ALL)) && isatty( 1 ))
		DFlags |= PROGRESS;

#ifdef __linux__
	if (DFlags & DEBUG_CRASH) {
		signal( SIGSEGV, crashHandler );
		signal( SIGBUS, crashHandler );
		signal( SIGILL, crashHandler );
	}
#endif

	if (merge_ops( cops, ops ))
		return 1;

	if (load_config( config, pseudo ))
		return 1;

	if (!channels) {
		fputs( "No channels defined. Try 'man " EXE "'\n", stderr );
		return 1;
	}

	if (mvars->all) {
		for (chan = channels; chan; chan = chan->next) {
			add_channel( &chanapp, chan, ops );
			if (!chan->patterns)
				boxes_total++;
		}
	} else {
		for (; argv[oind]; oind++) {
			for (group = groups; group; group = group->next) {
				if (!strcmp( group->name, argv[oind] )) {
					for (channame = group->channels; channame; channame = channame->next)
						if (!add_named_channel( &chanapp, channame->string, ops ))
							mvars->ret = 1;
					goto gotgrp;
				}
			}
			if (!add_named_channel( &chanapp, argv[oind], ops ))
				mvars->ret = 1;
		  gotgrp: ;
		}
	}
	if (!chans) {
		fputs( "No channel specified. Try '" EXE " -h'\n", stderr );
		return 1;
	}
	mvars->chanptr = chans;

	if (!mvars->list)
		stats();
	mvars->cben = 1;
	sync_chans( mvars, E_START );
	main_loop();
	if (!mvars->list)
		flushn();
	return mvars->ret;
}

#define ST_FRESH     0
#define ST_CONNECTED 1
#define ST_OPEN      2
#define ST_CANCELING 3
#define ST_CLOSED    4

static void
cancel_prep_done( void *aux )
{
	MVARS(aux)

	mvars->drv[t]->free_store( mvars->ctx[t] );
	mvars->state[t] = ST_CLOSED;
	sync_chans( mvars, E_OPEN );
}

static void
store_bad( void *aux )
{
	MVARS(aux)

	mvars->drv[t]->cancel_store( mvars->ctx[t] );
	mvars->state[t] = ST_CLOSED;
	mvars->ret = mvars->skip = 1;
	sync_chans( mvars, E_OPEN );
}

static void store_connected( int sts, void *aux );
static void store_listed( int sts, string_list_t *boxes, void *aux );
static int sync_listed_boxes( main_vars_t *mvars, box_ent_t *mbox );
static void done_sync_2_dyn( int sts, void *aux );
static void done_sync( int sts, void *aux );

#define nz(a,b) ((a)?(a):(b))

static void
sync_chans( main_vars_t *mvars, int ent )
{
	box_ent_t *mbox, *nmbox, **mboxapp;
	char **boxes[2];
	const char *labels[2];
	int t, mb, sb, cmp;

	if (!mvars->cben)
		return;
	switch (ent) {
	case E_OPEN: goto opened;
	case E_SYNC: goto syncone;
	}
	do {
		mvars->chan = mvars->chanptr->conf;
		info( "Channel %s\n", mvars->chan->name );
		mvars->skip = mvars->cben = 0;
		for (t = 0; t < 2; t++) {
			int st = mvars->chan->stores[t]->driver->get_fail_state( mvars->chan->stores[t] );
			if (st != FAIL_TEMP) {
				info( "Skipping due to %sfailed %s store %s.\n",
				      (st == FAIL_WAIT) ? "temporarily " : "", str_ms[t], mvars->chan->stores[t]->name );
				mvars->skip = 1;
			}
		}
		if (mvars->skip)
			goto next2;
		mvars->state[M] = mvars->state[S] = ST_FRESH;
		if ((DFlags & DEBUG_DRV) || (mvars->chan->stores[M]->driver->get_caps( 0 ) & mvars->chan->stores[S]->driver->get_caps( 0 ) & DRV_VERBOSE))
			labels[M] = "M: ", labels[S] = "S: ";
		else
			labels[M] = labels[S] = "";
		for (t = 0; t < 2; t++) {
			driver_t *drv = mvars->chan->stores[t]->driver;
			store_t *ctx = drv->alloc_store( mvars->chan->stores[t], labels[t] );
			if (DFlags & DEBUG_DRV) {
				drv = &proxy_driver;
				ctx = proxy_alloc_store( ctx, labels[t] );
			}
			mvars->drv[t] = drv;
			mvars->ctx[t] = ctx;
			drv->set_bad_callback( ctx, store_bad, AUX );
		}
		for (t = 0; ; t++) {
			info( "Opening %s store %s...\n", str_ms[t], mvars->chan->stores[t]->name );
			mvars->drv[t]->connect_store( mvars->ctx[t], store_connected, AUX );
			if (t || mvars->skip)
				break;
		}

		mvars->cben = 1;
	  opened:
		if (mvars->skip)
			goto next;
		if (mvars->state[M] != ST_OPEN || mvars->state[S] != ST_OPEN)
			return;

		if (!mvars->chanptr->boxlist && mvars->chan->patterns) {
			mvars->chanptr->boxlist = 2;
			boxes[M] = filter_boxes( mvars->boxes[M], mvars->chan->boxes[M], mvars->chan->patterns );
			boxes[S] = filter_boxes( mvars->boxes[S], mvars->chan->boxes[S], mvars->chan->patterns );
			mboxapp = &mvars->chanptr->boxes;
			for (mb = sb = 0; ; ) {
				char *mname = boxes[M] ? boxes[M][mb] : 0;
				char *sname = boxes[S] ? boxes[S][sb] : 0;
				if (!mname && !sname)
					break;
				mbox = nfmalloc( sizeof(*mbox) );
				if (!(cmp = !mname - !sname) && !(cmp = cmp_box_names( &mname, &sname ))) {
					mbox->name = mname;
					free( sname );
					mbox->present[M] = mbox->present[S] = BOX_PRESENT;
					mb++;
					sb++;
				} else if (cmp < 0) {
					mbox->name = mname;
					mbox->present[M] = BOX_PRESENT;
					mbox->present[S] = (!mb && !strcmp( mbox->name, "INBOX" )) ? BOX_PRESENT : BOX_ABSENT;
					mb++;
				} else {
					mbox->name = sname;
					mbox->present[M] = (!sb && !strcmp( mbox->name, "INBOX" )) ? BOX_PRESENT : BOX_ABSENT;
					mbox->present[S] = BOX_PRESENT;
					sb++;
				}
				mbox->next = 0;
				*mboxapp = mbox;
				mboxapp = &mbox->next;
				boxes_total++;
			}
			free( boxes[M] );
			free( boxes[S] );
			if (!mvars->list)
				stats();
		}
		mvars->boxptr = mvars->chanptr->boxes;

		if (mvars->list && chans_total > 1)
			printf( "%s:\n", mvars->chan->name );
	  syncml:
		mvars->done = mvars->cben = 0;
		if (mvars->chanptr->boxlist) {
			while ((mbox = mvars->boxptr)) {
				mvars->boxptr = mbox->next;
				if (sync_listed_boxes( mvars, mbox ))
					goto syncw;
			}
		} else {
			if (!mvars->list) {
				int present[] = { BOX_POSSIBLE, BOX_POSSIBLE };
				sync_boxes( mvars->ctx, mvars->chan->boxes, present, mvars->chan, done_sync, mvars );
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
		mvars->cben = 0;
		for (t = 0; t < 2; t++) {
			free_string_list( mvars->boxes[t] );
			mvars->boxes[t] = 0;
			if (mvars->state[t] == ST_FRESH) {
				/* An unconnected store may be only cancelled. */
				mvars->state[t] = ST_CLOSED;
				mvars->drv[t]->cancel_store( mvars->ctx[t] );
			} else if (mvars->state[t] == ST_CONNECTED || mvars->state[t] == ST_OPEN) {
				mvars->state[t] = ST_CANCELING;
				mvars->drv[t]->cancel_cmds( mvars->ctx[t], cancel_prep_done, AUX );
			}
		}
		mvars->cben = 1;
		if (mvars->state[M] != ST_CLOSED || mvars->state[S] != ST_CLOSED) {
			mvars->skip = 1;
			return;
		}
		if (mvars->chanptr->boxlist == 2) {
			for (nmbox = mvars->chanptr->boxes; (mbox = nmbox); ) {
				nmbox = mbox->next;
				free( mbox->name );
				free( mbox );
			}
			mvars->chanptr->boxes = 0;
			mvars->chanptr->boxlist = 0;
		}
	  next2:
		if (!mvars->list) {
			chans_done++;
			stats();
		}
	} while ((mvars->chanptr = mvars->chanptr->next));
	for (t = 0; t < N_DRIVERS; t++)
		drivers[t]->cleanup();
}

static void
store_connected( int sts, void *aux )
{
	MVARS(aux)
	string_list_t *cpat;
	int cflags;

	switch (sts) {
	case DRV_CANCELED:
		return;
	case DRV_OK:
		if (!mvars->skip && !mvars->chanptr->boxlist && mvars->chan->patterns) {
			for (cflags = 0, cpat = mvars->chan->patterns; cpat; cpat = cpat->next) {
				const char *pat = cpat->string;
				if (*pat != '!') {
					char buf[8];
					int bufl = snprintf( buf, sizeof(buf), "%s%s", nz( mvars->chan->boxes[t], "" ), pat );
					int flags = 0;
					/* Partial matches like "INB*" or even "*" are not considered,
					 * except implicity when the INBOX lives under Path. */
					if (starts_with( buf, bufl, "INBOX", 5 )) {
						char c = buf[5];
						if (!c) {
							/* User really wants the INBOX. */
							flags |= LIST_INBOX;
						} else if (c == '/') {
							/* Flattened sub-folders of INBOX actually end up in Path. */
							if (mvars->ctx[t]->conf->flat_delim)
								flags |= LIST_PATH;
							else
								flags |= LIST_INBOX;
						} else if (c == '*' || c == '%') {
							/* It can be both INBOX and Path, but don't require Path to be configured. */
							flags |= LIST_INBOX | LIST_PATH_MAYBE;
						} else {
							/* It's definitely not the INBOX. */
							flags |= LIST_PATH;
						}
					} else {
						flags |= LIST_PATH;
					}
					debug( "pattern '%s' (effective '%s'): %sPath, %sINBOX\n",
					       pat, buf, (flags & LIST_PATH) ? "" : "no ",  (flags & LIST_INBOX) ? "" : "no ");
					cflags |= flags;
				}
			}
			mvars->state[t] = ST_CONNECTED;
			mvars->drv[t]->list_store( mvars->ctx[t], cflags, store_listed, AUX );
			return;
		}
		mvars->state[t] = ST_OPEN;
		break;
	default:
		mvars->ret = mvars->skip = 1;
		mvars->state[t] = ST_OPEN;
		break;
	}
	sync_chans( mvars, E_OPEN );
}

static void
store_listed( int sts, string_list_t *boxes, void *aux )
{
	MVARS(aux)
	string_list_t *box;

	switch (sts) {
	case DRV_CANCELED:
		return;
	case DRV_OK:
		for (box = boxes; box; box = box->next) {
			if (mvars->ctx[t]->conf->flat_delim) {
				string_list_t *nbox;
				if (map_name( box->string, (char **)&nbox, offsetof(string_list_t, string), mvars->ctx[t]->conf->flat_delim, "/" ) < 0) {
					error( "Error: flattened mailbox name '%s' contains canonical hierarchy delimiter\n", box->string );
					mvars->ret = mvars->skip = 1;
				} else {
					nbox->next = mvars->boxes[t];
					mvars->boxes[t] = nbox;
				}
			} else {
				add_string_list( &mvars->boxes[t], box->string );
			}
		}
		if (mvars->ctx[t]->conf->map_inbox) {
			debug( "adding mapped inbox to %s: %s\n", str_ms[t], mvars->ctx[t]->conf->map_inbox );
			add_string_list( &mvars->boxes[t], mvars->ctx[t]->conf->map_inbox );
		}
		break;
	default:
		mvars->ret = mvars->skip = 1;
		break;
	}
	mvars->state[t] = ST_OPEN;
	sync_chans( mvars, E_OPEN );
}

static int
sync_listed_boxes( main_vars_t *mvars, box_ent_t *mbox )
{
	if (mvars->chan->boxes[M] || mvars->chan->boxes[S]) {
		const char *mpfx = nz( mvars->chan->boxes[M], "" );
		const char *spfx = nz( mvars->chan->boxes[S], "" );
		if (!mvars->list) {
			nfasprintf( &mvars->names[M], "%s%s", mpfx, mbox->name );
			nfasprintf( &mvars->names[S], "%s%s", spfx, mbox->name );
			sync_boxes( mvars->ctx, (const char **)mvars->names, mbox->present, mvars->chan, done_sync_2_dyn, mvars );
			return 1;
		}
		printf( "%s%s <=> %s%s\n", mpfx, mbox->name, spfx, mbox->name );
	} else {
		if (!mvars->list) {
			mvars->names[M] = mvars->names[S] = mbox->name;
			sync_boxes( mvars->ctx, (const char **)mvars->names, mbox->present, mvars->chan, done_sync, mvars );
			return 1;
		}
		puts( mbox->name );
	}
	return 0;
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
	boxes_done++;
	stats();
	if (sts) {
		mvars->ret = 1;
		if (sts & (SYNC_BAD(M) | SYNC_BAD(S))) {
			if (sts & SYNC_BAD(M))
				mvars->state[M] = ST_CLOSED;
			if (sts & SYNC_BAD(S))
				mvars->state[S] = ST_CLOSED;
			mvars->skip = 1;
		}
	}
	sync_chans( mvars, E_SYNC );
}
