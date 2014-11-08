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

#ifndef SOCKET_H
#define SOCKET_H

#include "common.h"

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct stack_st _STACK;

typedef struct server_conf {
	char *tunnel;
	char *host;
	int port;
#ifdef HAVE_LIBSSL
	char *cert_file;
	char use_imaps;
	char use_sslv2, use_sslv3, use_tlsv1, use_tlsv11, use_tlsv12;

	/* these are actually variables and are leaked at the end */
	char ssl_ctx_valid;
	_STACK *trusted_certs;
	SSL_CTX *SSLContext;
#endif
} server_conf_t;

typedef struct buff_chunk {
	struct buff_chunk *next;
	char *data;
	int len;
	char buf[1];
} buff_chunk_t;

typedef struct {
	/* connection */
	int fd;
	int state;
	const server_conf_t *conf; /* needed during connect */
#ifdef HAVE_IPV6
	struct addrinfo *addrs, *curr_addr; /* needed during connect */
#else
	char **curr_addr; /* needed during connect */
#endif
	char *name;
#ifdef HAVE_LIBSSL
	SSL *ssl;
	int force_trusted;
#endif

	void (*bad_callback)( void *aux ); /* async fail while sending or listening */
	void (*read_callback)( void *aux ); /* data available for reading */
	int (*write_callback)( void *aux ); /* all *queued* data was sent */
	union {
		void (*connect)( int ok, void *aux );
		void (*starttls)( int ok, void *aux );
	} callbacks;
	void *callback_aux;

	/* writing */
	buff_chunk_t *write_buf, **write_buf_append; /* buffer head & tail */
	int write_offset; /* offset into buffer head */

	/* reading */
	int offset; /* start of filled bytes in buffer */
	int bytes; /* number of filled bytes in buffer */
	int scanoff; /* offset to continue scanning for newline at, relative to 'offset' */
	char buf[100000];
} conn_t;

/* call this before doing anything with the socket */
static INLINE void socket_init( conn_t *conn,
                                const server_conf_t *conf,
                                void (*bad_callback)( void *aux ),
                                void (*read_callback)( void *aux ),
                                int (*write_callback)( void *aux ),
                                void *aux )
{
	conn->conf = conf;
	conn->bad_callback = bad_callback;
	conn->read_callback = read_callback;
	conn->write_callback = write_callback;
	conn->callback_aux = aux;
	conn->fd = -1;
	conn->name = 0;
	conn->write_buf_append = &conn->write_buf;
}
void socket_connect( conn_t *conn, void (*cb)( int ok, void *aux ) );
void socket_start_tls(conn_t *conn, void (*cb)( int ok, void *aux ) );
void socket_close( conn_t *sock );
int socket_read( conn_t *sock, char *buf, int len ); /* never waits */
char *socket_read_line( conn_t *sock ); /* don't free return value; never waits */
typedef enum { KeepOwn = 0, GiveOwn } ownership_t;
int socket_write( conn_t *sock, char *buf, int len, ownership_t takeOwn );

void cram( const char *challenge, const char *user, const char *pass,
           char **_final, int *_finallen );

#endif
