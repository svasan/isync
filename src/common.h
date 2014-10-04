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

#ifndef COMMON_H
#define COMMON_H

#include <autodefs.h>

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>

#define as(ar) (sizeof(ar)/sizeof(ar[0]))

#define __stringify(x) #x
#define stringify(x) __stringify(x)

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
# define ATTR_UNUSED __attribute__((unused))
# define ATTR_NORETURN __attribute__((noreturn))
# define ATTR_PRINTFLIKE(fmt,var) __attribute__((format(printf,fmt,var)))
#else
# define ATTR_UNUSED
# define ATTR_NORETURN
# define ATTR_PRINTFLIKE(fmt,var)
#endif

#ifdef __GNUC__
# define INLINE __inline__
#else
# define INLINE
#endif

#define EXE "mbsync"

/* main.c */

#define DEBUG        1
#define VERBOSE      2
#define XVERBOSE     4
#define QUIET        8
#define VERYQUIET    16
#define KEEPJOURNAL  32
#define ZERODELAY    64
#define CRASHDEBUG   128

extern int DFlags;
extern int UseFSync;

extern int Pid;
extern char Hostname[256];
extern const char *Home;

/* util.c */

void ATTR_PRINTFLIKE(1, 2) debug( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) debugn( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) info( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) infon( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) warn( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) error( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) sys_error( const char *, ... );
void flushn( void );

typedef struct string_list {
	struct string_list *next;
	char string[1];
} string_list_t;

void add_string_list_n( string_list_t **list, const char *str, int len );
void add_string_list( string_list_t **list, const char *str );
void free_string_list( string_list_t *list );

#ifndef HAVE_MEMRCHR
void *memrchr( const void *s, int c, size_t n );
#endif

int starts_with( const char *str, int strl, const char *cmp, int cmpl );
int equals( const char *str, int strl, const char *cmp, int cmpl );

#ifndef HAVE_TIMEGM
# include <time.h>
time_t timegm( struct tm *tm );
#endif

void *nfmalloc( size_t sz );
void *nfcalloc( size_t sz );
void *nfrealloc( void *mem, size_t sz );
char *nfstrdup( const char *str );
int nfvasprintf( char **str, const char *fmt, va_list va );
int ATTR_PRINTFLIKE(2, 3) nfasprintf( char **str, const char *fmt, ... );
int ATTR_PRINTFLIKE(3, 4) nfsnprintf( char *buf, int blen, const char *fmt, ... );
void ATTR_NORETURN oob( void );

char *expand_strdup( const char *s );

int map_name( const char *arg, char **result, int reserve, const char *in, const char *out );

void sort_ints( int *arr, int len );

void arc4_init( void );
unsigned char arc4_getbyte( void );

int bucketsForSize( int size );

#ifdef HAVE_SYS_POLL_H
# include <sys/poll.h>
#else
# define POLLIN 1
# define POLLOUT 4
# define POLLERR 8
#endif

void add_fd( int fd, void (*cb)( int events, void *aux ), void *aux );
void conf_fd( int fd, int and_events, int or_events );
void fake_fd( int fd, int events );
void del_fd( int fd );
void main_loop( void );

#endif
