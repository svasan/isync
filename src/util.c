/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2011,2012 Oswald Buddenhagen <ossi@users.sf.net>
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

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>

static int need_nl;

void
flushn( void )
{
	if (need_nl) {
		putchar( '\n' );
		fflush( stdout );
		need_nl = 0;
	}
}

static void
printn( const char *msg, va_list va )
{
	if (*msg == '\v')
		msg++;
	else
		flushn();
	vprintf( msg, va );
	fflush( stdout );
}

void
vdebug( int cat, const char *msg, va_list va )
{
	if (DFlags & cat) {
		vprintf( msg, va );
		fflush( stdout );
		need_nl = 0;
	}
}

void
vdebugn( int cat, const char *msg, va_list va )
{
	if (DFlags & cat) {
		vprintf( msg, va );
		fflush( stdout );
		need_nl = 1;
	}
}

void
progress( const char *msg, ... )
{
	va_list va;

	va_start( va, msg );
	vprintf( msg, va );
	va_end( va );
	fflush( stdout );
	need_nl = 1;
}

void
info( const char *msg, ... )
{
	va_list va;

	if (DFlags & VERBOSE) {
		va_start( va, msg );
		printn( msg, va );
		va_end( va );
		need_nl = 0;
	}
}

void
infon( const char *msg, ... )
{
	va_list va;

	if (DFlags & VERBOSE) {
		va_start( va, msg );
		printn( msg, va );
		va_end( va );
		need_nl = 1;
	}
}

void
notice( const char *msg, ... )
{
	va_list va;

	if (!(DFlags & QUIET)) {
		va_start( va, msg );
		printn( msg, va );
		va_end( va );
		need_nl = 0;
	}
}

void
warn( const char *msg, ... )
{
	va_list va;

	if (!(DFlags & VERYQUIET)) {
		flushn();
		va_start( va, msg );
		vfprintf( stderr, msg, va );
		va_end( va );
	}
}

void
error( const char *msg, ... )
{
	va_list va;

	flushn();
	va_start( va, msg );
	vfprintf( stderr, msg, va );
	va_end( va );
}

void
sys_error( const char *msg, ... )
{
	va_list va;
	char buf[1024];

	flushn();
	va_start( va, msg );
	if ((uint)vsnprintf( buf, sizeof(buf), msg, va ) >= sizeof(buf))
		oob();
	va_end( va );
	perror( buf );
}

void
add_string_list_n( string_list_t **list, const char *str, int len )
{
	string_list_t *elem;

	elem = nfmalloc( sizeof(*elem) + len );
	elem->next = *list;
	*list = elem;
	memcpy( elem->string, str, len );
	elem->string[len] = 0;
}

void
add_string_list( string_list_t **list, const char *str )
{
	add_string_list_n( list, str, strlen( str ) );
}

void
free_string_list( string_list_t *list )
{
	string_list_t *tlist;

	for (; list; list = tlist) {
		tlist = list->next;
		free( list );
	}
}

#ifndef HAVE_VASPRINTF
static int
vasprintf( char **strp, const char *fmt, va_list ap )
{
	int len;
	char tmp[1024];

	if ((len = vsnprintf( tmp, sizeof(tmp), fmt, ap )) < 0 || !(*strp = malloc( len + 1 )))
		return -1;
	if (len >= (int)sizeof(tmp))
		vsprintf( *strp, fmt, ap );
	else
		memcpy( *strp, tmp, len + 1 );
	return len;
}
#endif

#ifndef HAVE_MEMRCHR
void *
memrchr( const void *s, int c, size_t n )
{
	u_char *b = (u_char *)s, *e = b + n;

	while (--e >= b)
		if (*e == c)
			return (void *)e;
	return 0;
}
#endif

#ifndef HAVE_STRNLEN
size_t
strnlen( const char *str, size_t maxlen )
{
	const char *estr = memchr( str, 0, maxlen );
	return estr ? (size_t)(estr - str) : maxlen;
}

#endif

int
starts_with( const char *str, int strl, const char *cmp, int cmpl )
{
	if (strl < 0)
		strl = strnlen( str, cmpl + 1 );
	return (strl >= cmpl) && !memcmp( str, cmp, cmpl );
}

int
starts_with_upper( const char *str, int strl, const char *cmp, int cmpl )
{
	int i;

	if (strl < 0)
		strl = strnlen( str, cmpl + 1 );
	if (strl < cmpl)
		return 0;
	for (i = 0; i < cmpl; i++)
		if (str[i] != cmp[i] && toupper( str[i] ) != cmp[i])
			return 0;
	return 1;
}

int
equals( const char *str, int strl, const char *cmp, int cmpl )
{
	if (strl < 0)
		strl = strnlen( str, cmpl + 1 );
	return (strl == cmpl) && !memcmp( str, cmp, cmpl );
}

#ifndef HAVE_TIMEGM
/*
   Converts struct tm to time_t, assuming the data in tm is UTC rather
   than local timezone.

   mktime is similar but assumes struct tm, also known as the
   "broken-down" form of time, is in local time zone.  timegm
   uses mktime to make the conversion understanding that an offset
   will be introduced by the local time assumption.

   mktime_from_utc then measures the introduced offset by applying
   gmtime to the initial result and applying mktime to the resulting
   "broken-down" form.  The difference between the two mktime results
   is the measured offset which is then subtracted from the initial
   mktime result to yield a calendar time which is the value returned.

   tm_isdst in struct tm is set to 0 to force mktime to introduce a
   consistent offset (the non DST offset) since tm and tm+o might be
   on opposite sides of a DST change.

   Some implementations of mktime return -1 for the nonexistent
   localtime hour at the beginning of DST.  In this event, use
   mktime(tm - 1hr) + 3600.

   Schematically
     mktime(tm)   --> t+o
     gmtime(t+o)  --> tm+o
     mktime(tm+o) --> t+2o
     t+o - (t+2o - t+o) = t

   Contributed by Roger Beeman <beeman@cisco.com>, with the help of
   Mark Baushke <mdb@cisco.com> and the rest of the Gurus at CISCO.
   Further improved by Roger with assistance from Edward J. Sabol
   based on input by Jamie Zawinski.
*/

static time_t
my_mktime( struct tm *t )
{
	time_t tl = mktime( t );
	if (tl == -1) {
		t->tm_hour--;
		tl = mktime( t );
		if (tl != -1)
			tl += 3600;
	}
	return tl;
}

time_t
timegm( struct tm *t )
{
	time_t tl, tb;
	struct tm *tg;

	if ((tl = my_mktime( t )) == -1)
		return tl;
	tg = gmtime( &tl );
	tg->tm_isdst = 0;
	if ((tb = my_mktime( tg )) == -1)
		return tb;
	return tl - (tb - tl);
}
#endif

void
oob( void )
{
	fputs( "Fatal: buffer too small. Please report a bug.\n", stderr );
	abort();
}

int
nfsnprintf( char *buf, int blen, const char *fmt, ... )
{
	int ret;
	va_list va;

	va_start( va, fmt );
	if (blen <= 0 || (uint)(ret = vsnprintf( buf, blen, fmt, va )) >= (uint)blen)
		oob();
	va_end( va );
	return ret;
}

static void ATTR_NORETURN
oom( void )
{
	fputs( "Fatal: Out of memory\n", stderr );
	abort();
}

void *
nfmalloc( size_t sz )
{
	void *ret;

	if (!(ret = malloc( sz )))
		oom();
	return ret;
}

void *
nfcalloc( size_t sz )
{
	void *ret;

	if (!(ret = calloc( sz, 1 )))
		oom();
	return ret;
}

void *
nfrealloc( void *mem, size_t sz )
{
	char *ret;

	if (!(ret = realloc( mem, sz )) && sz)
		oom();
	return ret;
}

char *
nfstrndup( const char *str, size_t nchars )
{
	char *ret = nfmalloc( nchars + 1 );
	memcpy( ret, str, nchars );
	ret[nchars] = 0;
	return ret;
}

char *
nfstrdup( const char *str )
{
	return nfstrndup( str, strlen( str ) );
}

int
nfvasprintf( char **str, const char *fmt, va_list va )
{
	int ret = vasprintf( str, fmt, va );
	if (ret < 0)
		oom();
	return ret;
}

int
nfasprintf( char **str, const char *fmt, ... )
{
	int ret;
	va_list va;

	va_start( va, fmt );
	ret = nfvasprintf( str, fmt, va );
	va_end( va );
	return ret;
}

/*
static struct passwd *
cur_user( void )
{
	char *p;
	struct passwd *pw;
	uid_t uid;

	uid = getuid();
	if ((!(p = getenv("LOGNAME")) || !(pw = getpwnam( p )) || pw->pw_uid != uid) &&
	    (!(p = getenv("USER")) || !(pw = getpwnam( p )) || pw->pw_uid != uid) &&
	    !(pw = getpwuid( uid )))
	{
		fputs ("Cannot determinate current user\n", stderr);
		return 0;
	}
	return pw;
}
*/

char *
expand_strdup( const char *s )
{
	struct passwd *pw;
	const char *p, *q;
	char *r;

	if (*s == '~') {
		s++;
		if (!*s) {
			p = 0;
			q = Home;
		} else if (*s == '/') {
			p = s;
			q = Home;
		} else {
			if ((p = strchr( s, '/' ))) {
				r = nfstrndup( s, (int)(p - s) );
				pw = getpwnam( r );
				free( r );
			} else
				pw = getpwnam( s );
			if (!pw)
				return 0;
			q = pw->pw_dir;
		}
		nfasprintf( &r, "%s%s", q, p ? p : "" );
		return r;
	} else
		return nfstrdup( s );
}

/* Return value: 0 = ok, -1 = out found in arg, -2 = in found in arg but no out specified */
int
map_name( const char *arg, char **result, int reserve, const char *in, const char *out )
{
	char *p;
	int i, l, ll, num, inl, outl;

	l = strlen( arg );
	if (!in) {
	  copy:
		*result = nfmalloc( reserve + l + 1 );
		memcpy( *result + reserve, arg, l + 1 );
		return 0;
	}
	inl = strlen( in );
	if (out) {
		outl = strlen( out );
		if (inl == outl && !memcmp( in, out, inl ))
			goto copy;
	}
	for (num = 0, i = 0; i < l; ) {
		for (ll = 0; ll < inl; ll++)
			if (arg[i + ll] != in[ll])
				goto fout;
		num++;
		i += inl;
		continue;
	  fout:
		if (out) {
			for (ll = 0; ll < outl; ll++)
				if (arg[i + ll] != out[ll])
					goto fnexti;
			return -1;
		}
	  fnexti:
		i++;
	}
	if (!num)
		goto copy;
	if (!out)
		return -2;
	*result = nfmalloc( reserve + l + num * (outl - inl) + 1 );
	p = *result + reserve;
	for (i = 0; i < l; ) {
		for (ll = 0; ll < inl; ll++)
			if (arg[i + ll] != in[ll])
				goto rnexti;
#ifdef __GNUC__
# pragma GCC diagnostic push
/* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=42145 */
# pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
		memcpy( p, out, outl );
#ifdef __GNUC__
# pragma GCC diagnostic pop
#endif
		p += outl;
		i += inl;
		continue;
	  rnexti:
		*p++ = arg[i++];
	}
	*p = 0;
	return 0;
}

static int
compare_uints( const void *l, const void *r )
{
	return *(uint *)l - *(uint *)r;
}

void
sort_uint_array( uint_array_t array )
{
	qsort( array.data, array.size, sizeof(uint), compare_uints );
}

int
find_uint_array( uint_array_t array, uint value )
{
	int bot = 0, top = array.size - 1;
	while (bot <= top) {
		int i = (bot + top) / 2;
		uint elt = array.data[i];
		if (elt == value)
			return 1;
		if (elt < value)
			bot = i + 1;
		else
			top = i - 1;
	}
	return 0;
}


static struct {
	uchar i, j, s[256];
} rs;

void
arc4_init( void )
{
	int i, fd;
	uchar j, si, dat[128];

	if ((fd = open( "/dev/urandom", O_RDONLY )) < 0 && (fd = open( "/dev/random", O_RDONLY )) < 0) {
		error( "Fatal: no random number source available.\n" );
		exit( 3 );
	}
	if (read( fd, dat, 128 ) != 128) {
		error( "Fatal: cannot read random number source.\n" );
		exit( 3 );
	}
	close( fd );

	for (i = 0; i < 256; i++)
		rs.s[i] = i;
	for (i = j = 0; i < 256; i++) {
		si = rs.s[i];
		j += si + dat[i & 127];
		rs.s[i] = rs.s[j];
		rs.s[j] = si;
	}
	rs.i = rs.j = 0;

	for (i = 0; i < 256; i++)
		arc4_getbyte();
}

uchar
arc4_getbyte( void )
{
	uchar si, sj;

	rs.i++;
	si = rs.s[rs.i];
	rs.j += si;
	sj = rs.s[rs.j];
	rs.s[rs.i] = sj;
	rs.s[rs.j] = si;
	return rs.s[(si + sj) & 0xff];
}

static const uchar prime_deltas[] = {
    0,  0,  1,  3,  1,  5,  3,  3,  1,  9,  7,  5,  3, 17, 27,  3,
    1, 29,  3, 21,  7, 17, 15,  9, 43, 35, 15,  0,  0,  0,  0,  0
};

int
bucketsForSize( int size )
{
	int base = 4, bits = 2;

	for (;;) {
		int prime = base + prime_deltas[bits];
		if (prime >= size)
			return prime;
		base <<= 1;
		bits++;
	}
}

static void
list_prepend( list_head_t *head, list_head_t *to )
{
	assert( !head->next );
	assert( to->next );
	assert( to->prev->next == to );
	head->next = to;
	head->prev = to->prev;
	head->prev->next = head;
	to->prev = head;
}

static void
list_unlink( list_head_t *head )
{
	assert( head->next );
	assert( head->next->prev == head);
	assert( head->prev->next == head);
	head->next->prev = head->prev;
	head->prev->next = head->next;
	head->next = head->prev = 0;
}

static notifier_t *notifiers;
static int changed;  /* Iterator may be invalid now. */
#ifdef HAVE_SYS_POLL_H
static struct pollfd *pollfds;
static int npolls, rpolls;
#else
# ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
# endif
#endif

void
init_notifier( notifier_t *sn, int fd, void (*cb)( int, void * ), void *aux )
{
#ifdef HAVE_SYS_POLL_H
	int idx = npolls++;
	if (rpolls < npolls) {
		rpolls = npolls;
		pollfds = nfrealloc( pollfds, npolls * sizeof(*pollfds) );
	}
	pollfds[idx].fd = fd;
	pollfds[idx].events = 0; /* POLLERR & POLLHUP implicit */
	sn->index = idx;
#else
	sn->fd = fd;
	sn->events = 0;
#endif
	sn->cb = cb;
	sn->aux = aux;
	sn->next = notifiers;
	notifiers = sn;
}

void
conf_notifier( notifier_t *sn, int and_events, int or_events )
{
#ifdef HAVE_SYS_POLL_H
	int idx = sn->index;
	pollfds[idx].events = (pollfds[idx].events & and_events) | or_events;
#else
	sn->events = (sn->events & and_events) | or_events;
#endif
}

void
wipe_notifier( notifier_t *sn )
{
	notifier_t **snp;
#ifdef HAVE_SYS_POLL_H
	int idx;
#endif

	for (snp = &notifiers; *snp != sn; snp = &(*snp)->next)
		assert( *snp );
	*snp = sn->next;
	sn->next = 0;
	changed = 1;

#ifdef HAVE_SYS_POLL_H
	idx = sn->index;
	memmove( pollfds + idx, pollfds + idx + 1, (--npolls - idx) * sizeof(*pollfds) );
	for (sn = notifiers; sn; sn = sn->next) {
		if (sn->index > idx)
			sn->index--;
	}
#endif
}

static time_t
get_now( void )
{
	return time( 0 );
}

static list_head_t timers = { &timers, &timers };

void
init_wakeup( wakeup_t *tmr, void (*cb)( void * ), void *aux )
{
	tmr->cb = cb;
	tmr->aux = aux;
	tmr->links.next = tmr->links.prev = 0;
}

void
wipe_wakeup( wakeup_t *tmr )
{
	if (tmr->links.next)
		list_unlink( &tmr->links );
}

void
conf_wakeup( wakeup_t *tmr, int to )
{
	list_head_t *head, *succ;

	if (to < 0) {
		if (tmr->links.next)
			list_unlink( &tmr->links );
	} else {
		time_t timeout = to;
		if (!to) {
			/* We always prepend null timers, to cluster related events. */
			succ = timers.next;
		} else {
			timeout += get_now();
			/* We start at the end in the expectation that the newest timer is likely to fire last
			 * (which will be true only if all timeouts are equal, but it's an as good guess as any). */
			for (succ = &timers; (head = succ->prev) != &timers; succ = head) {
				if (head != &tmr->links && timeout > ((wakeup_t *)head)->timeout)
					break;
			}
			assert( head != &tmr->links );
		}
		tmr->timeout = timeout;
		if (succ != &tmr->links) {
			if (tmr->links.next)
				list_unlink( &tmr->links );
			list_prepend( &tmr->links, succ );
		}
	}
}

static void
event_wait( void )
{
	list_head_t *head;
	notifier_t *sn;
	int m;

#ifdef HAVE_SYS_POLL_H
	int timeout = -1;
	if ((head = timers.next) != &timers) {
		wakeup_t *tmr = (wakeup_t *)head;
		time_t delta = tmr->timeout;
		if (!delta || (delta -= get_now()) <= 0) {
			list_unlink( head );
			tmr->cb( tmr->aux );
			return;
		}
		timeout = (int)delta * 1000;
	}
	switch (poll( pollfds, npolls, timeout )) {
	case 0:
		return;
	case -1:
		perror( "poll() failed in event loop" );
		abort();
	default:
		break;
	}
	for (sn = notifiers; sn; sn = sn->next) {
		int n = sn->index;
		if ((m = pollfds[n].revents)) {
			assert( !(m & POLLNVAL) );
			sn->cb( m | shifted_bit( m, POLLHUP, POLLIN ), sn->aux );
			if (changed) {
				changed = 0;
				break;
			}
		}
	}
#else
	struct timeval *timeout = 0;
	struct timeval to_tv;
	fd_set rfds, wfds, efds;
	int fd;

	if ((head = timers.next) != &timers) {
		wakeup_t *tmr = (wakeup_t *)head;
		time_t delta = tmr->timeout;
		if (!delta || (delta -= get_now()) <= 0) {
			list_unlink( head );
			tmr->cb( tmr->aux );
			return;
		}
		to_tv.tv_sec = delta;
		to_tv.tv_usec = 0;
		timeout = &to_tv;
	}
	FD_ZERO( &rfds );
	FD_ZERO( &wfds );
	FD_ZERO( &efds );
	m = -1;
	for (sn = notifiers; sn; sn = sn->next) {
		fd = sn->fd;
		if (sn->events & POLLIN)
			FD_SET( fd, &rfds );
		if (sn->events & POLLOUT)
			FD_SET( fd, &wfds );
		FD_SET( fd, &efds );
		if (fd > m)
			m = fd;
	}
	switch (select( m + 1, &rfds, &wfds, &efds, timeout )) {
	case 0:
		return;
	case -1:
		perror( "select() failed in event loop" );
		abort();
	default:
		break;
	}
	for (sn = notifiers; sn; sn = sn->next) {
		fd = sn->fd;
		m = 0;
		if (FD_ISSET( fd, &rfds ))
			m |= POLLIN;
		if (FD_ISSET( fd, &wfds ))
			m |= POLLOUT;
		if (FD_ISSET( fd, &efds ))
			m |= POLLERR;
		if (m) {
			sn->cb( m, sn->aux );
			if (changed) {
				changed = 0;
				break;
			}
		}
	}
#endif
}

void
main_loop( void )
{
	while (notifiers || timers.next != &timers)
		event_wait();
}
