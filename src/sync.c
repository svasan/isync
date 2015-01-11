/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2010-2013 Oswald Buddenhagen <ossi@users.sf.net>
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

#include <assert.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#if !defined(_POSIX_SYNCHRONIZED_IO) || _POSIX_SYNCHRONIZED_IO <= 0
# define fdatasync fsync
#endif

channel_conf_t global_conf;
channel_conf_t *channels;
group_conf_t *groups;

const char *str_ms[] = { "master", "slave" }, *str_hl[] = { "push", "pull" };

void
Fclose( FILE *f, int safe )
{
	if ((safe && (fflush( f ) || (UseFSync && fdatasync( fileno( f ) )))) || fclose( f ) == EOF) {
		sys_error( "Error: cannot close file" );
		exit( 1 );
	}
}

void
Fprintf( FILE *f, const char *msg, ... )
{
	int r;
	va_list va;

	va_start( va, msg );
	r = vfprintf( f, msg, va );
	va_end( va );
	if (r < 0) {
		sys_error( "Error: cannot write file" );
		exit( 1 );
	}
}


static const char Flags[] = { 'D', 'F', 'R', 'S', 'T' };

static int
parse_flags( const char *buf )
{
	unsigned flags, i, d;

	for (flags = i = d = 0; i < as(Flags); i++)
		if (buf[d] == Flags[i]) {
			flags |= (1 << i);
			d++;
		}
	return flags;
}

static int
make_flags( int flags, char *buf )
{
	unsigned i, d;

	for (i = d = 0; i < as(Flags); i++)
		if (flags & (1 << i))
			buf[d++] = Flags[i];
	buf[d] = 0;
	return d;
}


#define S_DEAD         (1<<0)  /* ephemeral: the entry was killed and should be ignored */
#define S_DEL(ms)      (1<<(2+(ms)))  /* ephemeral: m/s message would be subject to expunge */
#define S_EXPIRED      (1<<4)  /* the entry is expired (slave message removal confirmed) */
#define S_EXPIRE       (1<<5)  /* the entry is being expired (slave message removal scheduled) */
#define S_NEXPIRE      (1<<6)  /* temporary: new expiration state */
#define S_DELETE       (1<<7)  /* ephemeral: flags propagation is a deletion */

#define mvBit(in,ib,ob) ((unsigned char)(((unsigned)in) * (ob) / (ib)))

typedef struct sync_rec {
	struct sync_rec *next;
	/* string_list_t *keywords; */
	int uid[2]; /* -2 = pending (use tuid), -1 = skipped (too big), 0 = expired */
	message_t *msg[2];
	unsigned char status, flags, aflags[2], dflags[2];
	char tuid[TUIDL];
} sync_rec_t;


/* cases:
   a) both non-null
   b) only master null
   b.1) uid[M] 0
   b.2) uid[M] -1
   b.3) master not scanned
   b.4) master gone
   c) only slave null
   c.1) uid[S] 0
   c.2) uid[S] -1
   c.3) slave not scanned
   c.4) slave gone
   d) both null
   d.1) both gone
   d.2) uid[M] 0, slave not scanned
   d.3) uid[M] -1, slave not scanned
   d.4) master gone, slave not scanned
   d.5) uid[M] 0, slave gone
   d.6) uid[M] -1, slave gone
   d.7) uid[S] 0, master not scanned
   d.8) uid[S] -1, master not scanned
   d.9) slave gone, master not scanned
   d.10) uid[S] 0, master gone
   d.11) uid[S] -1, master gone
   impossible cases: both uid[M] & uid[S] 0 or -1, both not scanned
*/

typedef struct {
	int t[2];
	void (*cb)( int sts, void *aux ), *aux;
	char *dname, *jname, *nname, *lname, *box_name[2];
	FILE *jfp, *nfp;
	sync_rec_t *srecs, **srecadd;
	channel_conf_t *chan;
	store_t *ctx[2];
	driver_t *drv[2];
	int state[2], ref_count, nsrecs, ret, lfd;
	int new_total[2], new_done[2];
	int flags_total[2], flags_done[2];
	int trash_total[2], trash_done[2];
	int maxuid[2]; /* highest UID that was already propagated */
	int newmaxuid[2]; /* highest UID that is currently being propagated */
	int uidval[2]; /* UID validity value */
	int newuid[2]; /* TUID lookup makes sense only for UIDs >= this */
	int mmaxxuid; /* highest expired UID on master during new message propagation */
	int smaxxuid; /* highest expired UID on slave */
} sync_vars_t;

static void sync_ref( sync_vars_t *svars ) { ++svars->ref_count; }
static void sync_deref( sync_vars_t *svars );
static int check_cancel( sync_vars_t *svars );

#define AUX &svars->t[t]
#define INV_AUX &svars->t[1-t]
#define DECL_SVARS \
	int t; \
	sync_vars_t *svars
#define INIT_SVARS(aux) \
	t = *(int *)aux; \
	svars = (sync_vars_t *)(((char *)(&((int *)aux)[-t])) - offsetof(sync_vars_t, t))
#define DECL_INIT_SVARS(aux) \
	int t = *(int *)aux; \
	sync_vars_t *svars = (sync_vars_t *)(((char *)(&((int *)aux)[-t])) - offsetof(sync_vars_t, t))

/* operation dependencies:
   select(x): -
   load(x): select(x)
   new(M), new(S), flags(M), flags(S): load(M) & load(S)
   find_new(x): new(x)
   trash(x): flags(x)
   close(x): trash(x) & find_new(x) & new(!x) // with expunge
   cleanup: close(M) & close(S)
*/

#define ST_LOADED          (1<<0)
#define ST_FIND_OLD        (1<<1)
#define ST_SENT_NEW        (1<<2)
#define ST_FIND_NEW        (1<<3)
#define ST_FOUND_NEW       (1<<4)
#define ST_SENT_FLAGS      (1<<5)
#define ST_SENT_TRASH      (1<<6)
#define ST_CLOSED          (1<<7)
#define ST_SENT_CANCEL     (1<<8)
#define ST_CANCELED        (1<<9)
#define ST_SELECTED        (1<<10)
#define ST_DID_EXPUNGE     (1<<11)
#define ST_CLOSING         (1<<12)


static void
match_tuids( sync_vars_t *svars, int t )
{
	sync_rec_t *srec;
	message_t *tmsg, *ntmsg = 0;
	const char *diag;
	int num_lost = 0;

	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		if (srec->uid[t] == -2 && srec->tuid[0]) {
			debug( "  pair(%d,%d): lookup %s, TUID %." stringify(TUIDL) "s\n", srec->uid[M], srec->uid[S], str_ms[t], srec->tuid );
			for (tmsg = ntmsg; tmsg; tmsg = tmsg->next) {
				if (tmsg->status & M_DEAD)
					continue;
				if (tmsg->tuid[0] && !memcmp( tmsg->tuid, srec->tuid, TUIDL )) {
					diag = (tmsg == ntmsg) ? "adjacently" : "after gap";
					goto mfound;
				}
			}
			for (tmsg = svars->ctx[t]->msgs; tmsg != ntmsg; tmsg = tmsg->next) {
				if (tmsg->status & M_DEAD)
					continue;
				if (tmsg->tuid[0] && !memcmp( tmsg->tuid, srec->tuid, TUIDL )) {
					diag = "after reset";
					goto mfound;
				}
			}
			debug( "  -> TUID lost\n" );
			Fprintf( svars->jfp, "& %d %d\n", srec->uid[M], srec->uid[S] );
			srec->flags = 0;
			srec->tuid[0] = 0;
			num_lost++;
			continue;
		  mfound:
			debug( "  -> new UID %d %s\n", tmsg->uid, diag );
			Fprintf( svars->jfp, "%c %d %d %d\n", "<>"[t], srec->uid[M], srec->uid[S], tmsg->uid );
			tmsg->srec = srec;
			srec->msg[t] = tmsg;
			ntmsg = tmsg->next;
			srec->uid[t] = tmsg->uid;
			srec->tuid[0] = 0;
		}
	}
	if (num_lost)
		warn( "Warning: lost track of %d %sed message(s)\n", num_lost, str_hl[t] );
}


typedef struct copy_vars {
	void (*cb)( int sts, int uid, struct copy_vars *vars );
	void *aux;
	sync_rec_t *srec; /* also ->tuid */
	message_t *msg;
	msg_data_t data;
} copy_vars_t;

static void msg_fetched( int sts, void *aux );

static void
copy_msg( copy_vars_t *vars )
{
	DECL_INIT_SVARS(vars->aux);

	t ^= 1;
	vars->data.flags = vars->msg->flags;
	vars->data.date = svars->chan->use_internal_date ? -1 : 0;
	svars->drv[t]->fetch_msg( svars->ctx[t], vars->msg, &vars->data, msg_fetched, vars );
}

static void msg_stored( int sts, int uid, void *aux );

static void
msg_fetched( int sts, void *aux )
{
	copy_vars_t *vars = (copy_vars_t *)aux;
	DECL_SVARS;
	char *fmap, *buf;
	int i, len, extra, scr, tcr, lcrs, hcrs, bcrs, lines;
	int start, sbreak = 0, ebreak = 0;
	char c;

	switch (sts) {
	case DRV_OK:
		INIT_SVARS(vars->aux);
		if (check_cancel( svars )) {
			free( vars->data.data );
			vars->cb( SYNC_CANCELED, 0, vars );
			return;
		}

		vars->msg->flags = vars->data.flags;

		scr = (svars->drv[1-t]->flags / DRV_CRLF) & 1;
		tcr = (svars->drv[t]->flags / DRV_CRLF) & 1;
		if (vars->srec || scr != tcr) {
			fmap = vars->data.data;
			len = vars->data.len;
			extra = lines = hcrs = bcrs = i = 0;
			if (vars->srec) {
			  nloop:
				start = i;
				lcrs = 0;
				while (i < len) {
					c = fmap[i++];
					if (c == '\r')
						lcrs++;
					else if (c == '\n') {
						if (starts_with( fmap + start, len - start, "X-TUID: ", 8 )) {
							extra = (sbreak = start) - (ebreak = i);
							goto oke;
						}
						lines++;
						hcrs += lcrs;
						if (i - lcrs - 1 == start) {
							sbreak = ebreak = start;
							goto oke;
						}
						goto nloop;
					}
				}
				/* invalid message */
				warn( "Warning: message %d from %s has incomplete header.\n",
				      vars->msg->uid, str_ms[1-t] );
				free( fmap );
				vars->cb( SYNC_NOGOOD, 0, vars );
				return;
			  oke:
				extra += 8 + TUIDL + 1 + (tcr && (!scr || hcrs));
			}
			if (tcr != scr) {
				for (; i < len; i++) {
					c = fmap[i];
					if (c == '\r')
						bcrs++;
					else if (c == '\n')
						lines++;
				}
				extra -= hcrs + bcrs;
				if (tcr)
					extra += lines;
			}

			vars->data.len = len + extra;
			buf = vars->data.data = nfmalloc( vars->data.len );
			i = 0;
			if (vars->srec) {
				if (tcr != scr) {
					if (tcr) {
						for (; i < sbreak; i++)
							if ((c = fmap[i]) != '\r') {
								if (c == '\n')
									*buf++ = '\r';
								*buf++ = c;
							}
					} else {
						for (; i < sbreak; i++)
							if ((c = fmap[i]) != '\r')
								*buf++ = c;
					}
				} else {
					memcpy( buf, fmap, sbreak );
					buf += sbreak;
				}

				memcpy( buf, "X-TUID: ", 8 );
				buf += 8;
				memcpy( buf, vars->srec->tuid, TUIDL );
				buf += TUIDL;
				if (tcr && (!scr || hcrs))
					*buf++ = '\r';
				*buf++ = '\n';
				i = ebreak;
			}
			if (tcr != scr) {
				if (tcr) {
					for (; i < len; i++)
						if ((c = fmap[i]) != '\r') {
							if (c == '\n')
								*buf++ = '\r';
							*buf++ = c;
						}
				} else {
					for (; i < len; i++)
						if ((c = fmap[i]) != '\r')
							*buf++ = c;
				}
			} else
				memcpy( buf, fmap + i, len - i );

			free( fmap );
		}

		svars->drv[t]->store_msg( svars->ctx[t], &vars->data, !vars->srec, msg_stored, vars );
		break;
	case DRV_CANCELED:
		vars->cb( SYNC_CANCELED, 0, vars );
		break;
	case DRV_MSG_BAD:
		vars->cb( SYNC_NOGOOD, 0, vars );
		break;
	default:
		vars->cb( SYNC_FAIL, 0, vars );
		break;
	}
}

static void
msg_stored( int sts, int uid, void *aux )
{
	copy_vars_t *vars = (copy_vars_t *)aux;
	DECL_SVARS;

	switch (sts) {
	case DRV_OK:
		vars->cb( SYNC_OK, uid, vars );
		break;
	case DRV_CANCELED:
		vars->cb( SYNC_CANCELED, 0, vars );
		break;
	case DRV_MSG_BAD:
		INIT_SVARS(vars->aux);
		(void)svars;
		warn( "Warning: %s refuses to store message %d from %s.\n",
		      str_ms[t], vars->msg->uid, str_ms[1-t] );
		vars->cb( SYNC_NOGOOD, 0, vars );
		break;
	default:
		vars->cb( SYNC_FAIL, 0, vars );
		break;
	}
}


static void
stats( sync_vars_t *svars )
{
	char buf[2][64];
	char *cs;
	int t, l;
	static int cols = -1;

	if (cols < 0 && (!(cs = getenv( "COLUMNS" )) || !(cols = atoi( cs ) / 2)))
		cols = 36;
	if (!(DFlags & QUIET)) {
		for (t = 0; t < 2; t++) {
			l = sprintf( buf[t], "+%d/%d *%d/%d #%d/%d",
			             svars->new_done[t], svars->new_total[t],
			             svars->flags_done[t], svars->flags_total[t],
			             svars->trash_done[t], svars->trash_total[t] );
			if (l > cols)
				buf[t][cols - 1] = '~';
		}
		infon( "\v\rM: %.*s  S: %.*s", cols, buf[0], cols, buf[1] );
	}
}


static void sync_bail( sync_vars_t *svars );
static void sync_bail1( sync_vars_t *svars );
static void sync_bail2( sync_vars_t *svars );
static void sync_bail3( sync_vars_t *svars );
static void cancel_done( void *aux );

static void
cancel_sync( sync_vars_t *svars )
{
	int t;

	for (t = 0; t < 2; t++) {
		int other_state = svars->state[1-t];
		if (svars->ret & SYNC_BAD(t)) {
			cancel_done( AUX );
		} else if (!(svars->state[t] & ST_SENT_CANCEL)) {
			/* ignore subsequent failures from in-flight commands */
			svars->state[t] |= ST_SENT_CANCEL;
			svars->drv[t]->cancel( svars->ctx[t], cancel_done, AUX );
		}
		if (other_state & ST_CANCELED)
			break;
	}
}

static void
cancel_done( void *aux )
{
	DECL_INIT_SVARS(aux);

	svars->state[t] |= ST_CANCELED;
	if (svars->state[1-t] & ST_CANCELED) {
		if (svars->lfd >= 0) {
			Fclose( svars->nfp, 0 );
			Fclose( svars->jfp, 0 );
			sync_bail( svars );
		} else {
			/* Early failure during box selection. */
			sync_bail2( svars );
		}
	}
}

static void
store_bad( void *aux )
{
	DECL_INIT_SVARS(aux);

	svars->drv[t]->cancel_store( svars->ctx[t] );
	svars->ret |= SYNC_BAD(t);
	cancel_sync( svars );
}

static int
check_cancel( sync_vars_t *svars )
{
	return (svars->state[M] | svars->state[S]) & (ST_SENT_CANCEL | ST_CANCELED);
}

static int
check_ret( int sts, void *aux )
{
	DECL_SVARS;

	if (sts == DRV_CANCELED)
		return 1;
	INIT_SVARS(aux);
	if (sts == DRV_BOX_BAD) {
		svars->ret |= SYNC_FAIL;
		cancel_sync( svars );
		return 1;
	}
	return check_cancel( svars );
}

#define SVARS_CHECK_RET \
	DECL_SVARS; \
	if (check_ret( sts, aux )) \
		return; \
	INIT_SVARS(aux)

#define SVARS_CHECK_RET_VARS(type) \
	type *vars = (type *)aux; \
	DECL_SVARS; \
	if (check_ret( sts, vars->aux )) { \
		free( vars ); \
		return; \
	} \
	INIT_SVARS(vars->aux)

#define SVARS_CHECK_CANCEL_RET \
	DECL_SVARS; \
	if (sts == SYNC_CANCELED) { \
		free( vars ); \
		return; \
	} \
	INIT_SVARS(vars->aux)

static char *
clean_strdup( const char *s )
{
	char *cs;
	int i;

	cs = nfstrdup( s );
	for (i = 0; cs[i]; i++)
		if (cs[i] == '/')
			cs[i] = '!';
	return cs;
}


#define JOURNAL_VERSION "2"

static void box_selected( int sts, void *aux );

void
sync_boxes( store_t *ctx[], const char *names[], channel_conf_t *chan,
            void (*cb)( int sts, void *aux ), void *aux )
{
	sync_vars_t *svars;
	int t;

	svars = nfcalloc( sizeof(*svars) );
	svars->t[1] = 1;
	svars->ref_count = 1;
	svars->cb = cb;
	svars->aux = aux;
	svars->ctx[0] = ctx[0];
	svars->ctx[1] = ctx[1];
	svars->chan = chan;
	svars->uidval[0] = svars->uidval[1] = -1;
	svars->srecadd = &svars->srecs;

	for (t = 0; t < 2; t++) {
		ctx[t]->orig_name =
			(!names[t] || (ctx[t]->conf->map_inbox && !strcmp( ctx[t]->conf->map_inbox, names[t] ))) ?
				"INBOX" : names[t];
		if (!ctx[t]->conf->flat_delim) {
			svars->box_name[t] = nfstrdup( ctx[t]->orig_name );
		} else if (map_name( ctx[t]->orig_name, &svars->box_name[t], 0, "/", ctx[t]->conf->flat_delim ) < 0) {
			error( "Error: canonical mailbox name '%s' contains flattened hierarchy delimiter\n", ctx[t]->orig_name );
			svars->ret = SYNC_FAIL;
			sync_bail3( svars );
			return;
		}
		ctx[t]->uidvalidity = -1;
		set_bad_callback( ctx[t], store_bad, AUX );
		svars->drv[t] = ctx[t]->conf->driver;
	}
	/* Both boxes must be fully set up at this point, so that error exit paths
	 * don't run into uninitialized variables. */
	sync_ref( svars );
	for (t = 0; t < 2; t++) {
		info( "Selecting %s %s...\n", str_ms[t], ctx[t]->orig_name );
		svars->drv[t]->select( ctx[t], svars->box_name[t], (chan->ops[t] & OP_CREATE) != 0, box_selected, AUX );
		if (check_cancel( svars ))
			break;
	}
	sync_deref( svars );
}

static void load_box( sync_vars_t *svars, int t, int minwuid, int *mexcs, int nmexcs );

static void
box_selected( int sts, void *aux )
{
	DECL_SVARS;
	sync_rec_t *srec, *nsrec;
	char *s, *cmname, *csname;
	store_t *ctx[2];
	channel_conf_t *chan;
	FILE *jfp;
	int opts[2], line, t1, t2, t3;
	int *mexcs, nmexcs, rmexcs, minwuid;
	struct stat st;
	struct flock lck;
	char fbuf[16]; /* enlarge when support for keywords is added */
	char buf[128], buf1[64], buf2[64];

	if (check_ret( sts, aux ))
		return;
	INIT_SVARS(aux);
	ctx[0] = svars->ctx[0];
	ctx[1] = svars->ctx[1];
	svars->state[t] |= ST_SELECTED;
	if (!(svars->state[1-t] & ST_SELECTED))
		return;

	chan = svars->chan;
	if (!strcmp( chan->sync_state ? chan->sync_state : global_conf.sync_state, "*" )) {
		if (!ctx[S]->path) {
			error( "Error: store '%s' does not support in-box sync state\n", chan->stores[S]->name );
		  sbail:
			svars->ret = SYNC_FAIL;
			sync_bail2( svars );
			return;
		}
		nfasprintf( &svars->dname, "%s/." EXE "state", ctx[S]->path );
	} else {
		csname = clean_strdup( svars->box_name[S] );
		if (chan->sync_state)
			nfasprintf( &svars->dname, "%s%s", chan->sync_state, csname );
		else {
			cmname = clean_strdup( svars->box_name[M] );
			nfasprintf( &svars->dname, "%s:%s:%s_:%s:%s", global_conf.sync_state,
			            chan->stores[M]->name, cmname, chan->stores[S]->name, csname );
			free( cmname );
		}
		free( csname );
		if (!(s = strrchr( svars->dname, '/' ))) {
			error( "Error: invalid SyncState location '%s'\n", svars->dname );
			goto sbail;
		}
		*s = 0;
		if (mkdir( svars->dname, 0700 ) && errno != EEXIST) {
			sys_error( "Error: cannot create SyncState directory '%s'", svars->dname );
			goto sbail;
		}
		*s = '/';
	}
	nfasprintf( &svars->jname, "%s.journal", svars->dname );
	nfasprintf( &svars->nname, "%s.new", svars->dname );
	nfasprintf( &svars->lname, "%s.lock", svars->dname );
	memset( &lck, 0, sizeof(lck) );
#if SEEK_SET != 0
	lck.l_whence = SEEK_SET;
#endif
#if F_WRLCK != 0
	lck.l_type = F_WRLCK;
#endif
	if ((svars->lfd = open( svars->lname, O_WRONLY|O_CREAT, 0666 )) < 0) {
		sys_error( "Error: cannot create lock file %s", svars->lname );
		svars->ret = SYNC_FAIL;
		sync_bail2( svars );
		return;
	}
	if (fcntl( svars->lfd, F_SETLK, &lck )) {
		error( "Error: channel :%s:%s-:%s:%s is locked\n",
		         chan->stores[M]->name, ctx[M]->orig_name, chan->stores[S]->name, ctx[S]->orig_name );
		svars->ret = SYNC_FAIL;
		sync_bail1( svars );
		return;
	}
	if ((jfp = fopen( svars->dname, "r" ))) {
		debug( "reading sync state %s ...\n", svars->dname );
		line = 0;
		while (fgets( buf, sizeof(buf), jfp )) {
			line++;
			if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
				error( "Error: incomplete sync state header entry at %s:%d\n", svars->dname, line );
			  jbail:
				fclose( jfp );
			  bail:
				svars->ret = SYNC_FAIL;
				sync_bail( svars );
				return;
			}
			if (t == 1)
				goto gothdr;
			if (line == 1 && isdigit( buf[0] )) {
				if (sscanf( buf, "%63s %63s", buf1, buf2 ) != 2 ||
				    sscanf( buf1, "%d:%d", &svars->uidval[M], &svars->maxuid[M] ) < 2 ||
				    sscanf( buf2, "%d:%d:%d", &svars->uidval[S], &svars->smaxxuid, &svars->maxuid[S] ) < 3) {
					error( "Error: invalid sync state header in %s\n", svars->dname );
					goto jbail;
				}
				goto gothdr;
			}
			if (sscanf( buf, "%63s %d", buf1, &t1 ) != 2) {
				error( "Error: malformed sync state header entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
			if (!strcmp( buf1, "MasterUidValidity" ))
				svars->uidval[M] = t1;
			else if (!strcmp( buf1, "SlaveUidValidity" ))
				svars->uidval[S] = t1;
			else if (!strcmp( buf1, "MaxPulledUid" ))
				svars->maxuid[M] = t1;
			else if (!strcmp( buf1, "MaxPushedUid" ))
				svars->maxuid[S] = t1;
			else if (!strcmp( buf1, "MaxExpiredSlaveUid" ))
				svars->smaxxuid = t1;
			else {
				error( "Error: unrecognized sync state header entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
		}
		error( "Error: unterminated sync state header in %s\n", svars->dname );
		goto jbail;
	  gothdr:
		while (fgets( buf, sizeof(buf), jfp )) {
			line++;
			if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
				error( "Error: incomplete sync state entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
			fbuf[0] = 0;
			if (sscanf( buf, "%d %d %15s", &t1, &t2, fbuf ) < 2) {
				error( "Error: invalid sync state entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
			srec = nfmalloc( sizeof(*srec) );
			srec->uid[M] = t1;
			srec->uid[S] = t2;
			s = fbuf;
			if (*s == 'X') {
				s++;
				srec->status = S_EXPIRE | S_EXPIRED;
			} else
				srec->status = 0;
			srec->flags = parse_flags( s );
			debug( "  entry (%d,%d,%u,%s)\n", srec->uid[M], srec->uid[S], srec->flags, srec->status & S_EXPIRED ? "X" : "" );
			srec->msg[M] = srec->msg[S] = 0;
			srec->tuid[0] = 0;
			srec->next = 0;
			*svars->srecadd = srec;
			svars->srecadd = &srec->next;
			svars->nsrecs++;
		}
		fclose( jfp );
	} else {
		if (errno != ENOENT) {
			sys_error( "Error: cannot read sync state %s", svars->dname );
			goto bail;
		}
	}
	svars->newmaxuid[M] = svars->maxuid[M];
	svars->newmaxuid[S] = svars->maxuid[S];
	svars->mmaxxuid = INT_MAX;
	line = 0;
	if ((jfp = fopen( svars->jname, "r" ))) {
		if (!stat( svars->nname, &st ) && fgets( buf, sizeof(buf), jfp )) {
			debug( "recovering journal ...\n" );
			if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
				error( "Error: incomplete journal header in %s\n", svars->jname );
				goto jbail;
			}
			if (!equals( buf, t, JOURNAL_VERSION "\n", strlen(JOURNAL_VERSION) + 1 )) {
				error( "Error: incompatible journal version "
				                 "(got %.*s, expected " JOURNAL_VERSION ")\n", t - 1, buf );
				goto jbail;
			}
			srec = 0;
			line = 1;
			while (fgets( buf, sizeof(buf), jfp )) {
				line++;
				if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
					error( "Error: incomplete journal entry at %s:%d\n", svars->jname, line );
					goto jbail;
				}
				if (buf[0] == '#' ?
				      (t3 = 0, (sscanf( buf + 2, "%d %d %n", &t1, &t2, &t3 ) < 2) || !t3 || (t - t3 != TUIDL + 3)) :
				      buf[0] == '(' || buf[0] == ')' || buf[0] == '{' || buf[0] == '}' || buf[0] == '!' ?
				        (sscanf( buf + 2, "%d", &t1 ) != 1) :
				        buf[0] == '+' || buf[0] == '&' || buf[0] == '-' || buf[0] == '|' || buf[0] == '/' || buf[0] == '\\' ?
				          (sscanf( buf + 2, "%d %d", &t1, &t2 ) != 2) :
				          (sscanf( buf + 2, "%d %d %d", &t1, &t2, &t3 ) != 3))
				{
					error( "Error: malformed journal entry at %s:%d\n", svars->jname, line );
					goto jbail;
				}
				if (buf[0] == '(')
					svars->maxuid[M] = t1;
				else if (buf[0] == ')')
					svars->maxuid[S] = t1;
				else if (buf[0] == '{')
					svars->newuid[M] = t1;
				else if (buf[0] == '}')
					svars->newuid[S] = t1;
				else if (buf[0] == '!')
					svars->smaxxuid = t1;
				else if (buf[0] == '|') {
					svars->uidval[M] = t1;
					svars->uidval[S] = t2;
				} else if (buf[0] == '+') {
					srec = nfmalloc( sizeof(*srec) );
					srec->uid[M] = t1;
					srec->uid[S] = t2;
					if (svars->newmaxuid[M] < t1)
						svars->newmaxuid[M] = t1;
					if (svars->newmaxuid[S] < t2)
						svars->newmaxuid[S] = t2;
					debug( "  new entry(%d,%d)\n", t1, t2 );
					srec->msg[M] = srec->msg[S] = 0;
					srec->status = 0;
					srec->flags = 0;
					srec->tuid[0] = 0;
					srec->next = 0;
					*svars->srecadd = srec;
					svars->srecadd = &srec->next;
					svars->nsrecs++;
				} else {
					for (nsrec = srec; srec; srec = srec->next)
						if (srec->uid[M] == t1 && srec->uid[S] == t2)
							goto syncfnd;
					for (srec = svars->srecs; srec != nsrec; srec = srec->next)
						if (srec->uid[M] == t1 && srec->uid[S] == t2)
							goto syncfnd;
					error( "Error: journal entry at %s:%d refers to non-existing sync state entry\n", svars->jname, line );
					goto jbail;
				  syncfnd:
					debugn( "  entry(%d,%d,%u) ", srec->uid[M], srec->uid[S], srec->flags );
					switch (buf[0]) {
					case '-':
						debug( "killed\n" );
						if (srec->msg[M])
							srec->msg[M]->srec = 0;
						srec->status = S_DEAD;
						break;
					case '#':
						debug( "TUID now %." stringify(TUIDL) "s\n", buf + t3 + 2 );
						memcpy( srec->tuid, buf + t3 + 2, TUIDL );
						break;
					case '&':
						debug( "TUID %." stringify(TUIDL) "s lost\n", srec->tuid );
						srec->flags = 0;
						srec->tuid[0] = 0;
						break;
					case '<':
						debug( "master now %d\n", t3 );
						srec->uid[M] = t3;
						srec->tuid[0] = 0;
						break;
					case '>':
						debug( "slave now %d\n", t3 );
						srec->uid[S] = t3;
						srec->tuid[0] = 0;
						break;
					case '*':
						debug( "flags now %d\n", t3 );
						srec->flags = t3;
						break;
					case '~':
						debug( "expire now %d\n", t3 );
						if (t3)
							srec->status |= S_EXPIRE;
						else
							srec->status &= ~S_EXPIRE;
						break;
					case '\\':
						t3 = (srec->status & S_EXPIRED);
						debug( "expire back to %d\n", t3 / S_EXPIRED );
						if (t3)
							srec->status |= S_EXPIRE;
						else
							srec->status &= ~S_EXPIRE;
						break;
					case '/':
						t3 = (srec->status & S_EXPIRE);
						debug( "expired now %d\n", t3 / S_EXPIRE );
						if (t3) {
							if (svars->smaxxuid < srec->uid[S])
								svars->smaxxuid = srec->uid[S];
							srec->status |= S_EXPIRED;
						} else
							srec->status &= ~S_EXPIRED;
						break;
					default:
						error( "Error: unrecognized journal entry at %s:%d\n", svars->jname, line );
						goto jbail;
					}
				}
			}
		}
		fclose( jfp );
	} else {
		if (errno != ENOENT) {
			sys_error( "Error: cannot read journal %s", svars->jname );
			goto bail;
		}
	}

	t1 = 0;
	for (t = 0; t < 2; t++)
		if (svars->uidval[t] >= 0 && svars->uidval[t] != ctx[t]->uidvalidity) {
			error( "Error: UIDVALIDITY of %s changed (got %d, expected %d)\n",
			       str_ms[t], ctx[t]->uidvalidity, svars->uidval[t] );
			t1++;
		}
	if (t1)
		goto bail;

	if (!(svars->nfp = fopen( svars->nname, "w" ))) {
		sys_error( "Error: cannot create new sync state %s", svars->nname );
		goto bail;
	}
	if (!(svars->jfp = fopen( svars->jname, "a" ))) {
		sys_error( "Error: cannot create journal %s", svars->jname );
		fclose( svars->nfp );
		goto bail;
	}
	setlinebuf( svars->jfp );
	if (!line)
		Fprintf( svars->jfp, JOURNAL_VERSION "\n" );

	opts[M] = opts[S] = 0;
	for (t = 0; t < 2; t++) {
		if (chan->ops[t] & (OP_DELETE|OP_FLAGS)) {
			opts[t] |= OPEN_SETFLAGS;
			opts[1-t] |= OPEN_OLD;
			if (chan->ops[t] & OP_FLAGS)
				opts[1-t] |= OPEN_FLAGS;
		}
		if (chan->ops[t] & (OP_NEW|OP_RENEW)) {
			opts[t] |= OPEN_APPEND;
			if (chan->ops[t] & OP_RENEW)
				opts[1-t] |= OPEN_OLD;
			if (chan->ops[t] & OP_NEW)
				opts[1-t] |= OPEN_NEW;
			if (chan->ops[t] & OP_EXPUNGE)
				opts[1-t] |= OPEN_FLAGS;
			if (chan->stores[t]->max_size != INT_MAX)
				opts[1-t] |= OPEN_SIZE;
		}
		if (chan->ops[t] & OP_EXPUNGE) {
			opts[t] |= OPEN_EXPUNGE;
			if (chan->stores[t]->trash) {
				if (!chan->stores[t]->trash_only_new)
					opts[t] |= OPEN_OLD;
				opts[t] |= OPEN_NEW|OPEN_FLAGS;
			} else if (chan->stores[1-t]->trash && chan->stores[1-t]->trash_remote_new)
				opts[t] |= OPEN_NEW|OPEN_FLAGS;
		}
	}
	if ((chan->ops[S] & (OP_NEW|OP_RENEW|OP_FLAGS)) && chan->max_messages)
		opts[S] |= OPEN_OLD|OPEN_NEW|OPEN_FLAGS;
	if (line)
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->tuid[0]) {
				if (srec->uid[M] == -2)
					opts[M] |= OPEN_NEW|OPEN_FIND, svars->state[M] |= ST_FIND_OLD;
				else if (srec->uid[S] == -2)
					opts[S] |= OPEN_NEW|OPEN_FIND, svars->state[S] |= ST_FIND_OLD;
				else
					assert( !"sync record with stray TUID" );
			}
		}
	svars->drv[M]->prepare_opts( ctx[M], opts[M] );
	svars->drv[S]->prepare_opts( ctx[S], opts[S] );

	mexcs = 0;
	nmexcs = rmexcs = 0;
	if (svars->ctx[M]->opts & OPEN_OLD) {
		if (chan->max_messages) {
			/* When messages have been expired on the slave, the master fetch is split into
			 * two ranges: The bulk fetch which corresponds with the most recent messages, and an
			 * exception list of messages which would have been expired if they weren't important. */
			debug( "preparing master selection - max expired slave uid is %d\n", svars->smaxxuid );
			/* First, find out the lower bound for the bulk fetch. */
			minwuid = INT_MAX;
			for (srec = svars->srecs; srec; srec = srec->next) {
				if ((srec->status & S_DEAD) || srec->uid[M] <= 0)
					continue;
				if (srec->status & S_EXPIRED) {
					if (!srec->uid[S]) {
						/* The expired message was already gone. */
						continue;
					}
					/* The expired message was not expunged yet, so re-examine it.
					 * This will happen en masse, so just extend the bulk fetch. */
				} else {
					if (svars->smaxxuid >= srec->uid[S]) {
						/* The non-expired message is in the generally expired range, so don't
						 * make it contribute to the bulk fetch. */
						continue;
					}
					/* Usual non-expired message. */
				}
				if (minwuid > srec->uid[M])
					minwuid = srec->uid[M];
			}
			debug( "  min non-orphaned master uid is %d\n", minwuid );
			/* Next, calculate the exception fetch. */
			for (srec = svars->srecs; srec; srec = srec->next) {
				if (srec->status & S_DEAD)
					continue;
				if (srec->uid[M] > 0 && srec->uid[S] > 0 && minwuid > srec->uid[M] &&
				    (!(svars->ctx[M]->opts & OPEN_NEW) || svars->maxuid[M] >= srec->uid[M])) {
					/* The pair is alive, but outside the bulk range. */
					if (nmexcs == rmexcs) {
						rmexcs = rmexcs * 2 + 100;
						mexcs = nfrealloc( mexcs, rmexcs * sizeof(int) );
					}
					mexcs[nmexcs++] = srec->uid[M];
				}
			}
			debugn( "  exception list is:" );
			for (t = 0; t < nmexcs; t++)
				debugn( " %d", mexcs[t] );
			debug( "\n" );
		} else {
			minwuid = 1;
		}
	} else {
		minwuid = INT_MAX;
	}
	sync_ref( svars );
	load_box( svars, M, minwuid, mexcs, nmexcs );
	if (!check_cancel( svars ))
		load_box( svars, S, (ctx[S]->opts & OPEN_OLD) ? 1 : INT_MAX, 0, 0 );
	sync_deref( svars );
}

static void box_loaded( int sts, void *aux );

static void
load_box( sync_vars_t *svars, int t, int minwuid, int *mexcs, int nmexcs )
{
	sync_rec_t *srec;
	int maxwuid;

	if (svars->ctx[t]->opts & OPEN_NEW) {
		if (minwuid > svars->maxuid[t] + 1)
			minwuid = svars->maxuid[t] + 1;
		maxwuid = INT_MAX;
	} else if (svars->ctx[t]->opts & OPEN_OLD) {
		maxwuid = 0;
		for (srec = svars->srecs; srec; srec = srec->next)
			if (!(srec->status & S_DEAD) && srec->uid[t] > maxwuid)
				maxwuid = srec->uid[t];
	} else
		maxwuid = 0;
	info( "Loading %s...\n", str_ms[t] );
	debug( maxwuid == INT_MAX ? "loading %s [%d,inf]\n" : "loading %s [%d,%d]\n", str_ms[t], minwuid, maxwuid );
	svars->drv[t]->load( svars->ctx[t], minwuid, maxwuid, svars->newuid[t], mexcs, nmexcs, box_loaded, AUX );
}

typedef struct {
	void *aux;
	sync_rec_t *srec;
	int aflags, dflags;
} flag_vars_t;

typedef struct {
	int uid;
	sync_rec_t *srec;
} sync_rec_map_t;

static void flags_set( int sts, void *aux );
static void flags_set_p2( sync_vars_t *svars, sync_rec_t *srec, int t );
static void msgs_flags_set( sync_vars_t *svars, int t );
static void msg_copied( int sts, int uid, copy_vars_t *vars );
static void msg_copied_p2( sync_vars_t *svars, sync_rec_t *srec, int t, int uid );
static void msgs_copied( sync_vars_t *svars, int t );

static void
box_loaded( int sts, void *aux )
{
	DECL_SVARS;
	sync_rec_t *srec;
	sync_rec_map_t *srecmap;
	message_t *tmsg;
	copy_vars_t *cv;
	flag_vars_t *fv;
	int uid, no[2], del[2], alive, todel, t1, t2;
	int sflags, nflags, aflags, dflags, nex;
	unsigned hashsz, idx;
	char fbuf[16]; /* enlarge when support for keywords is added */

	if (check_ret( sts, aux ))
		return;
	INIT_SVARS(aux);
	svars->state[t] |= ST_LOADED;
	info( "%s: %d messages, %d recent\n", str_ms[t], svars->ctx[t]->count, svars->ctx[t]->recent );

	if (svars->state[t] & ST_FIND_OLD) {
		debug( "matching previously copied messages on %s\n", str_ms[t] );
		match_tuids( svars, t );
	}

	debug( "matching messages on %s against sync records\n", str_ms[t] );
	hashsz = bucketsForSize( svars->nsrecs * 3 );
	srecmap = nfcalloc( hashsz * sizeof(*srecmap) );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		uid = srec->uid[t];
		idx = (unsigned)((unsigned)uid * 1103515245U) % hashsz;
		while (srecmap[idx].uid)
			if (++idx == hashsz)
				idx = 0;
		srecmap[idx].uid = uid;
		srecmap[idx].srec = srec;
	}
	for (tmsg = svars->ctx[t]->msgs; tmsg; tmsg = tmsg->next) {
		if (tmsg->srec) /* found by TUID */
			continue;
		uid = tmsg->uid;
		if (DFlags & DEBUG) {
			make_flags( tmsg->flags, fbuf );
			printf( svars->ctx[t]->opts & OPEN_SIZE ? "  message %5d, %-4s, %6lu: " : "  message %5d, %-4s: ", uid, fbuf, tmsg->size );
		}
		idx = (unsigned)((unsigned)uid * 1103515245U) % hashsz;
		while (srecmap[idx].uid) {
			if (srecmap[idx].uid == uid) {
				srec = srecmap[idx].srec;
				goto found;
			}
			if (++idx == hashsz)
				idx = 0;
		}
		debug( "new\n" );
		continue;
	  found:
		tmsg->srec = srec;
		srec->msg[t] = tmsg;
		debug( "pairs %5d\n", srec->uid[1-t] );
	}
	free( srecmap );

	if (!(svars->state[1-t] & ST_LOADED))
		return;

	if (svars->uidval[M] < 0 || svars->uidval[S] < 0) {
		svars->uidval[M] = svars->ctx[M]->uidvalidity;
		svars->uidval[S] = svars->ctx[S]->uidvalidity;
		Fprintf( svars->jfp, "| %d %d\n", svars->uidval[M], svars->uidval[S] );
	}

	info( "Synchronizing...\n" );

	debug( "synchronizing old entries\n" );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		debug( "pair (%d,%d)\n", srec->uid[M], srec->uid[S] );
		no[M] = !srec->msg[M] && (svars->ctx[M]->opts & OPEN_OLD);
		no[S] = !srec->msg[S] && (svars->ctx[S]->opts & OPEN_OLD);
		if (no[M] && no[S]) {
			debug( "  vanished\n" );
			/* d.1) d.5) d.6) d.10) d.11) */
			srec->status = S_DEAD;
			Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
		} else {
			del[M] = no[M] && (srec->uid[M] > 0);
			del[S] = no[S] && (srec->uid[S] > 0);

			for (t = 0; t < 2; t++) {
				srec->aflags[t] = srec->dflags[t] = 0;
				if (srec->msg[t] && (srec->msg[t]->flags & F_DELETED))
					srec->status |= S_DEL(t);
				/* excludes (push) c.3) d.2) d.3) d.4) / (pull) b.3) d.7) d.8) d.9) */
				if (!srec->uid[t]) {
					/* b.1) / c.1) */
					debug( "  no more %s\n", str_ms[t] );
				} else if (del[1-t]) {
					/* c.4) d.9) / b.4) d.4) */
					if ((t == M) && (srec->status & (S_EXPIRE|S_EXPIRED))) {
						/* Don't propagate deletion resulting from expiration. */
						debug( "  slave expired, orphaning master\n" );
						Fprintf( svars->jfp, "> %d %d 0\n", srec->uid[M], srec->uid[S] );
						srec->uid[S] = 0;
					} else {
						if (srec->msg[t] && (srec->msg[t]->status & M_FLAGS) && srec->msg[t]->flags != srec->flags)
							info( "Info: conflicting changes in (%d,%d)\n", srec->uid[M], srec->uid[S] );
						if (svars->chan->ops[t] & OP_DELETE) {
							debug( "  %sing delete\n", str_hl[t] );
							srec->aflags[t] = F_DELETED;
							srec->status |= S_DELETE;
						} else {
							debug( "  not %sing delete\n", str_hl[t] );
						}
					}
				} else if (!srec->msg[1-t])
					/* c.1) c.2) d.7) d.8) / b.1) b.2) d.2) d.3) */
					;
				else if (srec->uid[t] < 0)
					/* b.2) / c.2) */
					; /* handled as new messages (sort of) */
				else if (!del[t]) {
					/* a) & b.3) / c.3) */
					if (svars->chan->ops[t] & OP_FLAGS) {
						sflags = srec->msg[1-t]->flags;
						if ((t == M) && (srec->status & (S_EXPIRE|S_EXPIRED))) {
							/* Don't propagate deletion resulting from expiration. */
							debug( "  slave expiring\n" );
							sflags &= ~F_DELETED;
						}
						srec->aflags[t] = sflags & ~srec->flags;
						srec->dflags[t] = ~sflags & srec->flags;
						if (DFlags & DEBUG) {
							char afbuf[16], dfbuf[16]; /* enlarge when support for keywords is added */
							make_flags( srec->aflags[t], afbuf );
							make_flags( srec->dflags[t], dfbuf );
							debug( "  %sing flags: +%s -%s\n", str_hl[t], afbuf, dfbuf );
						}
					} else
						debug( "  not %sing flags\n", str_hl[t] );
				} /* else b.4) / c.4) */
			}
		}
	}

	debug( "synchronizing new entries\n" );
	for (t = 0; t < 2; t++) {
		for (tmsg = svars->ctx[1-t]->msgs; tmsg; tmsg = tmsg->next) {
			/* If we have a srec:
			 * - message is old (> 0) or expired (0) => ignore
			 * - message was skipped (-1) => ReNew
			 * - message was attempted, but failed (-2) => New
			 * If new have no srec, the message is always New. If messages were previously ignored
			 * due to being excessive, they would now appear to be newer than the messages that
			 * got actually synced, so make sure to look only at the newest ones. As some messages
			 * may be already propagated before an interruption, and maxuid logging is delayed,
			 * we need to track the newmaxuid separately. */
			srec = tmsg->srec;
			if (srec ? srec->uid[t] < 0 && (svars->chan->ops[t] & (srec->uid[t] == -1 ? OP_RENEW : OP_NEW))
			         : svars->newmaxuid[1-t] < tmsg->uid && (svars->chan->ops[t] & OP_NEW)) {
				debug( "new message %d on %s\n", tmsg->uid, str_ms[1-t] );
				if ((svars->chan->ops[t] & OP_EXPUNGE) && (tmsg->flags & F_DELETED)) {
					debug( "  -> not %sing - would be expunged anyway\n", str_hl[t] );
				} else {
					if (srec) {
						debug( "  -> pair(%d,%d) exists\n", srec->uid[M], srec->uid[S] );
					} else {
						srec = nfmalloc( sizeof(*srec) );
						srec->next = 0;
						*svars->srecadd = srec;
						svars->srecadd = &srec->next;
						svars->nsrecs++;
						srec->status = 0;
						srec->flags = 0;
						srec->tuid[0] = 0;
						srec->uid[1-t] = tmsg->uid;
						srec->uid[t] = -2;
						srec->msg[1-t] = tmsg;
						srec->msg[t] = 0;
						tmsg->srec = srec;
						if (svars->newmaxuid[1-t] < tmsg->uid)
							svars->newmaxuid[1-t] = tmsg->uid;
						Fprintf( svars->jfp, "+ %d %d\n", srec->uid[M], srec->uid[S] );
						debug( "  -> pair(%d,%d) created\n", srec->uid[M], srec->uid[S] );
					}
					if (svars->maxuid[1-t] < tmsg->uid) {
						/* We do this here for simplicity. However, logging must be delayed until
						 * all messages were propagated, as skipped messages could otherwise be
						 * logged before the propagation of messages with lower UIDs completes. */
						svars->maxuid[1-t] = tmsg->uid;
					}
					if ((tmsg->flags & F_FLAGGED) || tmsg->size <= svars->chan->stores[t]->max_size) {
						if (tmsg->flags) {
							srec->flags = tmsg->flags;
							Fprintf( svars->jfp, "* %d %d %u\n", srec->uid[M], srec->uid[S], srec->flags );
							debug( "  -> updated flags to %u\n", tmsg->flags );
						}
						for (t1 = 0; t1 < TUIDL; t1++) {
							t2 = arc4_getbyte() & 0x3f;
							srec->tuid[t1] = t2 < 26 ? t2 + 'A' : t2 < 52 ? t2 + 'a' - 26 : t2 < 62 ? t2 + '0' - 52 : t2 == 62 ? '+' : '/';
						}
						Fprintf( svars->jfp, "# %d %d %." stringify(TUIDL) "s\n", srec->uid[M], srec->uid[S], srec->tuid );
						debug( "  -> %sing message, TUID %." stringify(TUIDL) "s\n", str_hl[t], srec->tuid );
					} else {
						if (srec->uid[t] == -1) {
							debug( "  -> not %sing - still too big\n", str_hl[t] );
						} else {
							debug( "  -> not %sing - too big\n", str_hl[t] );
							msg_copied_p2( svars, srec, t, -1 );
						}
					}
				}
			}
		}
	}

	if ((svars->chan->ops[S] & (OP_NEW|OP_RENEW|OP_FLAGS)) && svars->chan->max_messages) {
		/* Note: When this branch is entered, we have loaded all slave messages. */
		/* Expire excess messages. Important (flagged, unread, or unpropagated) messages
		 * older than the first not expired message are not counted towards the total. */
		debug( "preparing message expiration\n" );
		alive = 0;
		for (tmsg = svars->ctx[S]->msgs; tmsg; tmsg = tmsg->next) {
			if (tmsg->status & M_DEAD)
				continue;
			if ((srec = tmsg->srec) && srec->uid[M] > 0 &&
			    ((tmsg->flags | srec->aflags[S]) & ~srec->dflags[S] & F_DELETED) &&
			    !(srec->status & (S_EXPIRE|S_EXPIRED))) {
				/* Message was not propagated yet, or is deleted. */
			} else {
				alive++;
			}
		}
		for (tmsg = svars->ctx[M]->msgs; tmsg; tmsg = tmsg->next) {
			if ((srec = tmsg->srec) && srec->tuid[0] && !(tmsg->flags & F_DELETED))
				alive++;
		}
		todel = alive - svars->chan->max_messages;
		debug( "%d alive messages, %d excess - expiring\n", alive, todel );
		alive = 0;
		for (tmsg = svars->ctx[S]->msgs; tmsg; tmsg = tmsg->next) {
			if (tmsg->status & M_DEAD)
				continue;
			if (!(srec = tmsg->srec) || srec->uid[M] <= 0) {
				/* We did not push the message, so it must be kept. */
				debug( "  message %d unpropagated\n", tmsg->uid );
				todel--;
			} else {
				nflags = (tmsg->flags | srec->aflags[S]) & ~srec->dflags[S];
				if (!(nflags & F_DELETED) || (srec->status & (S_EXPIRE|S_EXPIRED))) {
					/* The message is not deleted, or is already (being) expired. */
					if ((nflags & F_FLAGGED) || !((nflags & F_SEEN) || ((void)(todel > 0 && alive++), svars->chan->expire_unread > 0))) {
						/* Important messages are always kept. */
						debug( "  old pair(%d,%d) important\n", srec->uid[M], srec->uid[S] );
						todel--;
					} else if (todel > 0 ||
					           ((srec->status & (S_EXPIRE|S_EXPIRED)) == (S_EXPIRE|S_EXPIRED)) ||
					           ((srec->status & (S_EXPIRE|S_EXPIRED)) && (tmsg->flags & F_DELETED))) {
						/* The message is excess or was already (being) expired. */
						srec->status |= S_NEXPIRE;
						debug( "  old pair(%d,%d) expired\n", srec->uid[M], srec->uid[S] );
						todel--;
					}
				}
			}
		}
		for (tmsg = svars->ctx[M]->msgs; tmsg; tmsg = tmsg->next) {
			if ((srec = tmsg->srec) && srec->tuid[0]) {
				nflags = tmsg->flags;
				if (!(nflags & F_DELETED)) {
					if ((nflags & F_FLAGGED) || !((nflags & F_SEEN) || ((void)(todel > 0 && alive++), svars->chan->expire_unread > 0))) {
						/* Important messages are always fetched. */
						debug( "  new pair(%d,%d) important\n", srec->uid[M], srec->uid[S] );
						todel--;
					} else if (todel > 0) {
						/* The message is excess. */
						srec->status |= S_NEXPIRE;
						debug( "  new pair(%d,%d) expired\n", srec->uid[M], srec->uid[S] );
						svars->mmaxxuid = srec->uid[M];
						todel--;
					}
				}
			}
		}
		debug( "%d excess messages remain\n", todel );
		if (svars->chan->expire_unread < 0 && (unsigned)alive * 2 > svars->chan->max_messages) {
			error( "%s: %d unread messages in excess of MaxMessages (%d).\n"
			       "Please set ExpireUnread to decide outcome. Skipping mailbox.\n",
			       svars->ctx[S]->orig_name, alive, svars->chan->max_messages );
			svars->ret |= SYNC_FAIL;
			cancel_sync( svars );
			return;
		}
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (!srec->tuid[0]) {
				if (!srec->msg[S])
					continue;
				nex = (srec->status / S_NEXPIRE) & 1;
				if (nex != ((srec->status / S_EXPIRED) & 1)) {
					/* The record needs a state change ... */
					if (nex != ((srec->status / S_EXPIRE) & 1)) {
						/* ... and we need to start a transaction. */
						Fprintf( svars->jfp, "~ %d %d %d\n", srec->uid[M], srec->uid[S], nex );
						debug( "  pair(%d,%d): %d (pre)\n", srec->uid[M], srec->uid[S], nex );
						srec->status = (srec->status & ~S_EXPIRE) | (nex * S_EXPIRE);
					} else {
						/* ... but the "right" transaction is already pending. */
						debug( "  pair(%d,%d): %d (pending)\n", srec->uid[M], srec->uid[S], nex );
					}
				} else {
					/* Note: the "wrong" transaction may be pending here,
					 * e.g.: S_NEXPIRE = 0, S_EXPIRE = 1, S_EXPIRED = 0. */
				}
			} else {
				if (srec->status & S_NEXPIRE) {
					Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
					debug( "  pair(%d,%d): 1 (abort)\n", srec->uid[M], srec->uid[S] );
					srec->msg[M]->srec = 0;
					srec->status = S_DEAD;
				}
			}
		}
	}

	sync_ref( svars );

	debug( "synchronizing flags\n" );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if ((srec->status & S_DEAD) || srec->uid[M] <= 0 || srec->uid[S] <= 0)
			continue;
		for (t = 0; t < 2; t++) {
			aflags = srec->aflags[t];
			dflags = srec->dflags[t];
			if (srec->status & S_DELETE) {
				if (!aflags) {
					/* This deletion propagation goes the other way round. */
					continue;
				}
			} else {
				/* The trigger is an expiration transaction being ongoing ... */
				if ((t == S) && ((mvBit(srec->status, S_EXPIRE, S_EXPIRED) ^ srec->status) & S_EXPIRED)) {
					/* ... but the actual action derives from the wanted state. */
					if (srec->status & S_NEXPIRE)
						aflags |= F_DELETED;
					else
						dflags |= F_DELETED;
				}
			}
			if ((svars->chan->ops[t] & OP_EXPUNGE) && (((srec->msg[t] ? srec->msg[t]->flags : 0) | aflags) & ~dflags & F_DELETED) &&
			    (!svars->ctx[t]->conf->trash || svars->ctx[t]->conf->trash_only_new))
			{
				/* If the message is going to be expunged, don't propagate anything but the deletion. */
				srec->aflags[t] &= F_DELETED;
				aflags &= F_DELETED;
				srec->dflags[t] = dflags = 0;
			}
			if (srec->msg[t] && (srec->msg[t]->status & M_FLAGS)) {
				/* If we know the target message's state, optimize away non-changes. */
				aflags &= ~srec->msg[t]->flags;
				dflags &= srec->msg[t]->flags;
			}
			if (aflags | dflags) {
				svars->flags_total[t]++;
				stats( svars );
				fv = nfmalloc( sizeof(*fv) );
				fv->aux = AUX;
				fv->srec = srec;
				fv->aflags = aflags;
				fv->dflags = dflags;
				svars->drv[t]->set_flags( svars->ctx[t], srec->msg[t], srec->uid[t], aflags, dflags, flags_set, fv );
				if (check_cancel( svars ))
					goto out;
			} else
				flags_set_p2( svars, srec, t );
		}
	}
	for (t = 0; t < 2; t++) {
		svars->drv[t]->commit( svars->ctx[t] );
		svars->state[t] |= ST_SENT_FLAGS;
		msgs_flags_set( svars, t );
		if (check_cancel( svars ))
			goto out;
	}

	debug( "propagating new messages\n" );
	if (UseFSync)
		fdatasync( fileno( svars->jfp ) );
	for (t = 0; t < 2; t++) {
		svars->newuid[t] = svars->ctx[t]->uidnext;
		Fprintf( svars->jfp, "%c %d\n", "{}"[t], svars->newuid[t] );
		for (tmsg = svars->ctx[1-t]->msgs; tmsg; tmsg = tmsg->next) {
			if ((srec = tmsg->srec) && srec->tuid[0]) {
				svars->new_total[t]++;
				stats( svars );
				cv = nfmalloc( sizeof(*cv) );
				cv->cb = msg_copied;
				cv->aux = AUX;
				cv->srec = srec;
				cv->msg = tmsg;
				copy_msg( cv );
				if (check_cancel( svars ))
					goto out;
			}
		}
		svars->state[t] |= ST_SENT_NEW;
		msgs_copied( svars, t );
		if (check_cancel( svars ))
			goto out;
	}

  out:
	sync_deref( svars );
}

static void
msg_copied( int sts, int uid, copy_vars_t *vars )
{
	SVARS_CHECK_CANCEL_RET;
	switch (sts) {
	case SYNC_OK:
		if (uid < 0)
			svars->state[t] |= ST_FIND_NEW;
		msg_copied_p2( svars, vars->srec, t, uid );
		break;
	case SYNC_NOGOOD:
		debug( "  -> killing (%d,%d)\n", vars->srec->uid[M], vars->srec->uid[S] );
		vars->srec->status = S_DEAD;
		Fprintf( svars->jfp, "- %d %d\n", vars->srec->uid[M], vars->srec->uid[S] );
		break;
	default:
		cancel_sync( svars );
		free( vars );
		return;
	}
	free( vars );
	svars->new_done[t]++;
	stats( svars );
	msgs_copied( svars, t );
}

static void
msg_copied_p2( sync_vars_t *svars, sync_rec_t *srec, int t, int uid )
{
	/* Possible previous UIDs:
	 * - -2 when the entry is new
	 * - -1 when re-newing an entry
	 * Possible new UIDs:
	 * - a real UID when storing a message to a UIDPLUS mailbox
	 * - -2 when storing a message to a dumb mailbox
	 * - -1 when not actually storing a message */
	if (srec->uid[t] != uid) {
		debug( "  -> new UID %d on %s\n", uid, str_ms[t] );
		Fprintf( svars->jfp, "%c %d %d %d\n", "<>"[t], srec->uid[M], srec->uid[S], uid );
		srec->uid[t] = uid;
		srec->tuid[0] = 0;
	}
	if (t == S && svars->mmaxxuid < srec->uid[M]) {
		/* If we have so many new messages that some of them are instantly expired,
		 * but some are still propagated because they are important, we need to
		 * ensure explicitly that the bulk fetch limit is upped. */
		svars->mmaxxuid = INT_MAX;
		if (svars->smaxxuid < srec->uid[S] - 1) {
			svars->smaxxuid = srec->uid[S] - 1;
			Fprintf( svars->jfp, "! %d\n", svars->smaxxuid );
		}
	}
}

static void msgs_found_new( int sts, void *aux );
static void msgs_new_done( sync_vars_t *svars, int t );
static void sync_close( sync_vars_t *svars, int t );

static void
msgs_copied( sync_vars_t *svars, int t )
{
	if (!(svars->state[t] & ST_SENT_NEW) || svars->new_done[t] < svars->new_total[t])
		return;

	sync_ref( svars );

	Fprintf( svars->jfp, "%c %d\n", ")("[t], svars->maxuid[1-t] );
	sync_close( svars, 1-t );
	if (check_cancel( svars ))
		goto out;

	if (svars->state[t] & ST_FIND_NEW) {
		debug( "finding just copied messages on %s\n", str_ms[t] );
		svars->drv[t]->find_new_msgs( svars->ctx[t], svars->newuid[t], msgs_found_new, AUX );
	} else {
		msgs_new_done( svars, t );
	}

  out:
	sync_deref( svars );
}

static void
msgs_found_new( int sts, void *aux )
{
	SVARS_CHECK_RET;
	switch (sts) {
	case DRV_OK:
		debug( "matching just copied messages on %s\n", str_ms[t] );
		break;
	default:
		warn( "Warning: cannot find newly stored messages on %s.\n", str_ms[t] );
		break;
	}
	match_tuids( svars, t );
	msgs_new_done( svars, t );
}

static void
msgs_new_done( sync_vars_t *svars, int t )
{
	svars->state[t] |= ST_FOUND_NEW;
	sync_close( svars, t );
}

static void
flags_set( int sts, void *aux )
{
	SVARS_CHECK_RET_VARS(flag_vars_t);
	switch (sts) {
	case DRV_OK:
		if (vars->aflags & F_DELETED)
			vars->srec->status |= S_DEL(t);
		else if (vars->dflags & F_DELETED)
			vars->srec->status &= ~S_DEL(t);
		flags_set_p2( svars, vars->srec, t );
		break;
	}
	free( vars );
	svars->flags_done[t]++;
	stats( svars );
	msgs_flags_set( svars, t );
}

static void
flags_set_p2( sync_vars_t *svars, sync_rec_t *srec, int t )
{
	if (srec->status & S_DELETE) {
		debug( "  pair(%d,%d): resetting %s UID\n", srec->uid[M], srec->uid[S], str_ms[1-t] );
		Fprintf( svars->jfp, "%c %d %d 0\n", "><"[t], srec->uid[M], srec->uid[S] );
		srec->uid[1-t] = 0;
	} else {
		int nflags = (srec->flags | srec->aflags[t]) & ~srec->dflags[t];
		if (srec->flags != nflags) {
			debug( "  pair(%d,%d): updating flags (%u -> %u; %sed)\n", srec->uid[M], srec->uid[S], srec->flags, nflags, str_hl[t] );
			srec->flags = nflags;
			Fprintf( svars->jfp, "* %d %d %u\n", srec->uid[M], srec->uid[S], nflags );
		}
		if (t == S) {
			int nex = (srec->status / S_NEXPIRE) & 1;
			if (nex != ((srec->status / S_EXPIRED) & 1)) {
				if (nex && (svars->smaxxuid < srec->uid[S]))
					svars->smaxxuid = srec->uid[S];
				Fprintf( svars->jfp, "/ %d %d\n", srec->uid[M], srec->uid[S] );
				debug( "  pair(%d,%d): expired %d (commit)\n", srec->uid[M], srec->uid[S], nex );
				srec->status = (srec->status & ~S_EXPIRED) | (nex * S_EXPIRED);
			} else if (nex != ((srec->status / S_EXPIRE) & 1)) {
				Fprintf( svars->jfp, "\\ %d %d\n", srec->uid[M], srec->uid[S] );
				debug( "  pair(%d,%d): expire %d (cancel)\n", srec->uid[M], srec->uid[S], nex );
				srec->status = (srec->status & ~S_EXPIRE) | (nex * S_EXPIRE);
			}
		}
	}
}

static void msg_trashed( int sts, void *aux );
static void msg_rtrashed( int sts, int uid, copy_vars_t *vars );

static void
msgs_flags_set( sync_vars_t *svars, int t )
{
	message_t *tmsg;
	copy_vars_t *cv;

	if (!(svars->state[t] & ST_SENT_FLAGS) || svars->flags_done[t] < svars->flags_total[t])
		return;

	sync_ref( svars );

	if ((svars->chan->ops[t] & OP_EXPUNGE) &&
	    (svars->ctx[t]->conf->trash || (svars->ctx[1-t]->conf->trash && svars->ctx[1-t]->conf->trash_remote_new))) {
		debug( "trashing in %s\n", str_ms[t] );
		for (tmsg = svars->ctx[t]->msgs; tmsg; tmsg = tmsg->next)
			if ((tmsg->flags & F_DELETED) && (t == M || !tmsg->srec || !(tmsg->srec->status & (S_EXPIRE|S_EXPIRED)))) {
				if (svars->ctx[t]->conf->trash) {
					if (!svars->ctx[t]->conf->trash_only_new || !tmsg->srec || tmsg->srec->uid[1-t] < 0) {
						debug( "%s: trashing message %d\n", str_ms[t], tmsg->uid );
						svars->trash_total[t]++;
						stats( svars );
						svars->drv[t]->trash_msg( svars->ctx[t], tmsg, msg_trashed, AUX );
						if (check_cancel( svars ))
							goto out;
					} else
						debug( "%s: not trashing message %d - not new\n", str_ms[t], tmsg->uid );
				} else {
					if (!tmsg->srec || tmsg->srec->uid[1-t] < 0) {
						if (tmsg->size <= svars->ctx[1-t]->conf->max_size) {
							debug( "%s: remote trashing message %d\n", str_ms[t], tmsg->uid );
							svars->trash_total[t]++;
							stats( svars );
							cv = nfmalloc( sizeof(*cv) );
							cv->cb = msg_rtrashed;
							cv->aux = INV_AUX;
							cv->srec = 0;
							cv->msg = tmsg;
							copy_msg( cv );
							if (check_cancel( svars ))
								goto out;
						} else
							debug( "%s: not remote trashing message %d - too big\n", str_ms[t], tmsg->uid );
					} else
						debug( "%s: not remote trashing message %d - not new\n", str_ms[t], tmsg->uid );
				}
			}
	}
	svars->state[t] |= ST_SENT_TRASH;
	sync_close( svars, t );

  out:
	sync_deref( svars );
}

static void
msg_trashed( int sts, void *aux )
{
	DECL_SVARS;

	if (sts == DRV_MSG_BAD)
		sts = DRV_BOX_BAD;
	if (check_ret( sts, aux ))
		return;
	INIT_SVARS(aux);
	svars->trash_done[t]++;
	stats( svars );
	sync_close( svars, t );
}

static void
msg_rtrashed( int sts, int uid ATTR_UNUSED, copy_vars_t *vars )
{
	SVARS_CHECK_CANCEL_RET;
	switch (sts) {
	case SYNC_OK:
	case SYNC_NOGOOD: /* the message is gone or heavily busted */
		break;
	default:
		cancel_sync( svars );
		free( vars );
		return;
	}
	free( vars );
	t ^= 1;
	svars->trash_done[t]++;
	stats( svars );
	sync_close( svars, t );
}

static void box_closed( int sts, void *aux );
static void box_closed_p2( sync_vars_t *svars, int t );

static void
sync_close( sync_vars_t *svars, int t )
{
	if ((~svars->state[t] & (ST_FOUND_NEW|ST_SENT_TRASH)) || svars->trash_done[t] < svars->trash_total[t] ||
	    !(svars->state[1-t] & ST_SENT_NEW) || svars->new_done[1-t] < svars->new_total[1-t])
		return;

	if (svars->state[t] & ST_CLOSING)
		return;
	svars->state[t] |= ST_CLOSING;

	if ((svars->chan->ops[t] & OP_EXPUNGE) /*&& !(svars->state[t] & ST_TRASH_BAD)*/) {
		debug( "expunging %s\n", str_ms[t] );
		svars->drv[t]->close( svars->ctx[t], box_closed, AUX );
	} else {
		box_closed_p2( svars, t );
	}
}

static void
box_closed( int sts, void *aux )
{
	SVARS_CHECK_RET;
	svars->state[t] |= ST_DID_EXPUNGE;
	box_closed_p2( svars, t );
}

static void
box_closed_p2( sync_vars_t *svars, int t )
{
	sync_rec_t *srec;
	int minwuid;
	char fbuf[16]; /* enlarge when support for keywords is added */

	svars->state[t] |= ST_CLOSED;
	if (!(svars->state[1-t] & ST_CLOSED))
		return;

	if (((svars->state[M] | svars->state[S]) & ST_DID_EXPUNGE) || svars->chan->max_messages) {
		debug( "purging obsolete entries\n" );

		minwuid = INT_MAX;
		if (svars->chan->max_messages) {
			debug( "  max expired slave uid is %d\n", svars->smaxxuid );
			for (srec = svars->srecs; srec; srec = srec->next) {
				if (srec->status & S_DEAD)
					continue;
				if (!((srec->uid[S] <= 0 || ((srec->status & S_DEL(S)) && (svars->state[S] & ST_DID_EXPUNGE))) &&
				      (srec->uid[M] <= 0 || ((srec->status & S_DEL(M)) && (svars->state[M] & ST_DID_EXPUNGE)) || (srec->status & S_EXPIRED))) &&
				    svars->smaxxuid < srec->uid[S] && minwuid > srec->uid[M])
					minwuid = srec->uid[M];
			}
			debug( "  min non-orphaned master uid is %d\n", minwuid );
		}

		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[S] <= 0 || ((srec->status & S_DEL(S)) && (svars->state[S] & ST_DID_EXPUNGE))) {
				if (srec->uid[M] <= 0 || ((srec->status & S_DEL(M)) && (svars->state[M] & ST_DID_EXPUNGE)) ||
				    ((srec->status & S_EXPIRED) && svars->maxuid[M] >= srec->uid[M] && minwuid > srec->uid[M])) {
					debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
					srec->status = S_DEAD;
					Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
				} else if (srec->uid[S] > 0) {
					debug( "  -> orphaning (%d,[%d])\n", srec->uid[M], srec->uid[S] );
					Fprintf( svars->jfp, "> %d %d 0\n", srec->uid[M], srec->uid[S] );
					srec->uid[S] = 0;
				}
			} else if (srec->uid[M] > 0 && ((srec->status & S_DEL(M)) && (svars->state[M] & ST_DID_EXPUNGE))) {
				debug( "  -> orphaning ([%d],%d)\n", srec->uid[M], srec->uid[S] );
				Fprintf( svars->jfp, "< %d %d 0\n", srec->uid[M], srec->uid[S] );
				srec->uid[M] = 0;
			}
		}
	}

	Fprintf( svars->nfp,
	         "MasterUidValidity %d\nSlaveUidValidity %d\nMaxPulledUid %d\nMaxPushedUid %d\n",
	         svars->uidval[M], svars->uidval[S], svars->maxuid[M], svars->maxuid[S] );
	if (svars->smaxxuid)
		Fprintf( svars->nfp, "MaxExpiredSlaveUid %d\n", svars->smaxxuid );
	Fprintf( svars->nfp, "\n" );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		make_flags( srec->flags, fbuf );
		Fprintf( svars->nfp, "%d %d %s%s\n", srec->uid[M], srec->uid[S],
		         srec->status & S_EXPIRED ? "X" : "", fbuf );
	}

	Fclose( svars->nfp, 1 );
	Fclose( svars->jfp, 0 );
	if (!(DFlags & KEEPJOURNAL)) {
		/* order is important! */
		if (rename( svars->nname, svars->dname ))
			warn( "Warning: cannot commit sync state %s\n", svars->dname );
		else if (unlink( svars->jname ))
			warn( "Warning: cannot delete journal %s\n", svars->jname );
	}

	sync_bail( svars );
}

static void
sync_bail( sync_vars_t *svars )
{
	sync_rec_t *srec, *nsrec;

	for (srec = svars->srecs; srec; srec = nsrec) {
		nsrec = srec->next;
		free( srec );
	}
	unlink( svars->lname );
	sync_bail1( svars );
}

static void
sync_bail1( sync_vars_t *svars )
{
	close( svars->lfd );
	sync_bail2( svars );
}

static void
sync_bail2( sync_vars_t *svars )
{
	free( svars->lname );
	free( svars->nname );
	free( svars->jname );
	free( svars->dname );
	flushn();
	sync_bail3( svars );
}

static void
sync_bail3( sync_vars_t *svars )
{
	free( svars->box_name[M] );
	free( svars->box_name[S] );
	sync_deref( svars );
}

static void
sync_deref( sync_vars_t *svars )
{
	if (!--svars->ref_count) {
		void (*cb)( int sts, void *aux ) = svars->cb;
		void *aux = svars->aux;
		int ret = svars->ret;
		free( svars );
		cb( ret, aux );
	}
}
