/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2008,2010,2011, 2013 Oswald Buddenhagen <ossi@users.sf.net>
 * Copyright (C) 2004 Theodore Y. Ts'o <tytso@mit.edu>
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

#include "socket.h"

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_LIBSSL
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/x509v3.h>
# if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define X509_OBJECT_get0_X509(o) ((o)->data.x509)
#  define X509_STORE_get0_objects(o) ((o)->objs)
# endif
#endif

enum {
	SCK_CONNECTING,
#ifdef HAVE_LIBSSL
	SCK_STARTTLS,
#endif
	SCK_READY,
	SCK_EOF
};

static void
socket_fail( conn_t *conn )
{
	conn->bad_callback( conn->callback_aux );
}

#ifdef HAVE_LIBSSL
static int
ssl_return( const char *func, conn_t *conn, int ret )
{
	int err;

	switch ((err = SSL_get_error( conn->ssl, ret ))) {
	case SSL_ERROR_NONE:
		return ret;
	case SSL_ERROR_WANT_WRITE:
		conf_notifier( &conn->notify, POLLIN, POLLOUT );
		FALLTHROUGH
	case SSL_ERROR_WANT_READ:
		return 0;
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
		if (!(err = ERR_get_error())) {
			if (ret == 0) {
	case SSL_ERROR_ZERO_RETURN:
				/* Callers take the short path out, so signal higher layers from here. */
				conn->state = SCK_EOF;
				conn->read_callback( conn->callback_aux );
				return -1;
			}
			sys_error( "Socket error: secure %s %s", func, conn->name );
		} else {
			error( "Socket error: secure %s %s: %s\n", func, conn->name, ERR_error_string( err, 0 ) );
		}
		break;
	default:
		error( "Socket error: secure %s %s: unhandled SSL error %d\n", func, conn->name, err );
		break;
	}
	if (conn->state == SCK_STARTTLS)
		conn->callbacks.starttls( 0, conn->callback_aux );
	else
		socket_fail( conn );
	return -1;
}

/* Some of this code is inspired by / lifted from mutt. */

static int
host_matches( const char *host, const char *pattern )
{
	if (pattern[0] == '*' && pattern[1] == '.') {
		pattern += 2;
		if (!(host = strchr( host, '.' )))
			return 0;
		host++;
	}

	return *host && *pattern && !strcasecmp( host, pattern );
}

static int
verify_hostname( X509 *cert, const char *hostname )
{
	int i, len, found;
	X509_NAME *subj;
	STACK_OF(GENERAL_NAME) *subj_alt_names;
	char cname[1000];

	/* try the DNS subjectAltNames */
	found = 0;
	if ((subj_alt_names = X509_get_ext_d2i( cert, NID_subject_alt_name, NULL, NULL ))) {
		int num_subj_alt_names = sk_GENERAL_NAME_num( subj_alt_names );
		for (i = 0; i < num_subj_alt_names; i++) {
			GENERAL_NAME *subj_alt_name = sk_GENERAL_NAME_value( subj_alt_names, i );
			if (subj_alt_name->type == GEN_DNS &&
			    strlen( (const char *)subj_alt_name->d.ia5->data ) == (size_t)subj_alt_name->d.ia5->length &&
			    host_matches( hostname, (const char *)(subj_alt_name->d.ia5->data) ))
			{
				found = 1;
				break;
			}
		}
		sk_GENERAL_NAME_pop_free( subj_alt_names, GENERAL_NAME_free );
	}
	if (found)
		return 0;

	/* try the common name */
	if (!(subj = X509_get_subject_name( cert ))) {
		error( "Error, cannot get certificate subject\n" );
		return -1;
	}
	if ((len = X509_NAME_get_text_by_NID( subj, NID_commonName, cname, sizeof(cname) )) < 0) {
		error( "Error, cannot get certificate common name\n" );
		return -1;
	}
	if (strlen( cname ) == (size_t)len && host_matches( hostname, cname ))
		return 0;

	error( "Error, certificate owner does not match hostname %s\n", hostname );
	return -1;
}

static int
verify_cert_host( const server_conf_t *conf, conn_t *sock )
{
	int i;
	long err;
	X509 *cert;
	STACK_OF(X509_OBJECT) *trusted;

	cert = SSL_get_peer_certificate( sock->ssl );
	if (!cert) {
		error( "Error, no server certificate\n" );
		return -1;
	}

	trusted = (STACK_OF(X509_OBJECT) *)sock->conf->trusted_certs;
	for (i = 0; i < sk_X509_OBJECT_num( trusted ); i++) {
		if (!X509_cmp( cert, X509_OBJECT_get0_X509( sk_X509_OBJECT_value( trusted, i ) ) ))
			return 0;
	}

	err = SSL_get_verify_result( sock->ssl );
	if (err != X509_V_OK) {
		error( "SSL error connecting %s: %s\n", sock->name, X509_verify_cert_error_string( err ) );
		return -1;
	}

	if (!conf->host) {
		error( "SSL error connecting %s: Neither host nor matching certificate specified\n", sock->name );
		return -1;
	}

	return verify_hostname( cert, conf->host );
}

static int
init_ssl_ctx( const server_conf_t *conf )
{
	server_conf_t *mconf = (server_conf_t *)conf;
	int options = 0;

	if (conf->SSLContext)
		return conf->ssl_ctx_valid;

	mconf->SSLContext = SSL_CTX_new( SSLv23_client_method() );

	if (!(conf->ssl_versions & SSLv3))
		options |= SSL_OP_NO_SSLv3;
	if (!(conf->ssl_versions & TLSv1))
		options |= SSL_OP_NO_TLSv1;
#ifdef SSL_OP_NO_TLSv1_1
	if (!(conf->ssl_versions & TLSv1_1))
		options |= SSL_OP_NO_TLSv1_1;
#endif
#ifdef SSL_OP_NO_TLSv1_2
	if (!(conf->ssl_versions & TLSv1_2))
		options |= SSL_OP_NO_TLSv1_2;
#endif

	SSL_CTX_set_options( mconf->SSLContext, options );

	if (conf->cert_file && !SSL_CTX_load_verify_locations( mconf->SSLContext, conf->cert_file, 0 )) {
		error( "Error while loading certificate file '%s': %s\n",
		       conf->cert_file, ERR_error_string( ERR_get_error(), 0 ) );
		return 0;
	}
	mconf->trusted_certs = (_STACK *)sk_X509_OBJECT_dup( X509_STORE_get0_objects( SSL_CTX_get_cert_store( mconf->SSLContext ) ) );
	if (mconf->system_certs && !SSL_CTX_set_default_verify_paths( mconf->SSLContext ))
		warn( "Warning: Unable to load default certificate files: %s\n",
		      ERR_error_string( ERR_get_error(), 0 ) );

	SSL_CTX_set_verify( mconf->SSLContext, SSL_VERIFY_NONE, NULL );

	if (conf->client_certfile && !SSL_CTX_use_certificate_chain_file( mconf->SSLContext, conf->client_certfile)) {
		error( "Error while loading client certificate file '%s': %s\n",
		       conf->client_certfile, ERR_error_string( ERR_get_error(), 0 ) );
		return 0;
	}
	if (conf->client_keyfile && !SSL_CTX_use_PrivateKey_file( mconf->SSLContext, conf->client_keyfile, SSL_FILETYPE_PEM)) {
		error( "Error while loading client private key '%s': %s\n",
		       conf->client_keyfile, ERR_error_string( ERR_get_error(), 0 ) );
		return 0;
	}

	mconf->ssl_ctx_valid = 1;
	return 1;
}

static void start_tls_p2( conn_t * );
static void start_tls_p3( conn_t *, int );
static void ssl_fake_cb( void * );

void
socket_start_tls( conn_t *conn, void (*cb)( int ok, void *aux ) )
{
	static int ssl_inited;

	conn->callbacks.starttls = cb;

	if (!ssl_inited) {
		SSL_library_init();
		SSL_load_error_strings();
		ssl_inited = 1;
	}

	if (!init_ssl_ctx( conn->conf )) {
		start_tls_p3( conn, 0 );
		return;
	}

	init_wakeup( &conn->ssl_fake, ssl_fake_cb, conn );
	conn->ssl = SSL_new( ((server_conf_t *)conn->conf)->SSLContext );
	SSL_set_fd( conn->ssl, conn->fd );
	SSL_set_mode( conn->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER );
	socket_expect_read( conn, 1 );
	conn->state = SCK_STARTTLS;
	start_tls_p2( conn );
}

static void
start_tls_p2( conn_t *conn )
{
	if (ssl_return( "connect to", conn, SSL_connect( conn->ssl ) ) > 0) {
		if (verify_cert_host( conn->conf, conn )) {
			start_tls_p3( conn, 0 );
		} else {
			info( "Connection is now encrypted\n" );
			start_tls_p3( conn, 1 );
		}
	}
}

static void start_tls_p3( conn_t *conn, int ok )
{
	socket_expect_read( conn, 0 );
	conn->state = SCK_READY;
	conn->callbacks.starttls( ok, conn->callback_aux );
}

#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBZ

static void z_fake_cb( void * );

static const char *
z_err_msg( int code, z_streamp strm )
{
	/* zlib's consistency in populating z_stream->msg is somewhat
	 * less than stellar. zError() is undocumented. */
	return strm->msg ? strm->msg : zError( code );
}

void
socket_start_deflate( conn_t *conn )
{
	int result;

	conn->in_z = nfcalloc( sizeof(*conn->in_z) );
	result = inflateInit2(
			conn->in_z,
			-15 /* Use raw deflate */
		);
	if (result != Z_OK) {
		error( "Fatal: Cannot initialize decompression: %s\n", z_err_msg( result, conn->in_z ) );
		abort();
	}

	conn->out_z = nfcalloc( sizeof(*conn->out_z) );
	result = deflateInit2(
			conn->out_z,
			Z_DEFAULT_COMPRESSION, /* Compression level */
			Z_DEFLATED, /* Only valid value */
			-15, /* Use raw deflate */
			8, /* Default memory usage */
			Z_DEFAULT_STRATEGY /* Don't try to do anything fancy */
		);
	if (result != Z_OK) {
		error( "Fatal: Cannot initialize compression: %s\n", z_err_msg( result, conn->out_z ) );
		abort();
	}

	init_wakeup( &conn->z_fake, z_fake_cb, conn );
}
#endif /* HAVE_LIBZ */

static void socket_fd_cb( int, void * );
static void socket_fake_cb( void * );
static void socket_timeout_cb( void * );

static void socket_connect_one( conn_t * );
static void socket_connect_next( conn_t * );
static void socket_connect_failed( conn_t * );
static void socket_connected( conn_t * );
static void socket_connect_bail( conn_t * );

static void
socket_open_internal( conn_t *sock, int fd )
{
	sock->fd = fd;
	fcntl( fd, F_SETFL, O_NONBLOCK );
	init_notifier( &sock->notify, fd, socket_fd_cb, sock );
	init_wakeup( &sock->fd_fake, socket_fake_cb, sock );
	init_wakeup( &sock->fd_timeout, socket_timeout_cb, sock );
}

static void
socket_close_internal( conn_t *sock )
{
	wipe_notifier( &sock->notify );
	wipe_wakeup( &sock->fd_fake );
	wipe_wakeup( &sock->fd_timeout );
	close( sock->fd );
	sock->fd = -1;
}

void
socket_connect( conn_t *sock, void (*cb)( int ok, void *aux ) )
{
	const server_conf_t *conf = sock->conf;

	sock->callbacks.connect = cb;

	/* open connection to server */
	if (conf->tunnel) {
		int a[2];

		nfasprintf( &sock->name, "tunnel '%s'", conf->tunnel );
		infon( "Starting %s... ", sock->name );

		if (socketpair( PF_UNIX, SOCK_STREAM, 0, a )) {
			perror( "socketpair" );
			exit( 1 );
		}

		if (fork() == 0) {
			if (dup2( a[0], 0 ) == -1 || dup2( a[0], 1 ) == -1)
				_exit( 127 );
			close( a[0] );
			close( a[1] );
			execl( "/bin/sh", "sh", "-c", conf->tunnel, (char *)0 );
			_exit( 127 );
		}

		close( a[0] );
		socket_open_internal( sock, a[1] );

		info( "\vok\n" );
		socket_connected( sock );
	} else {
#ifdef HAVE_IPV6
		int gaierr;
		struct addrinfo hints;

		memset( &hints, 0, sizeof(hints) );
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_ADDRCONFIG;
		infon( "Resolving %s... ", conf->host );
		if ((gaierr = getaddrinfo( conf->host, NULL, &hints, &sock->addrs ))) {
			error( "Error: Cannot resolve server '%s': %s\n", conf->host, gai_strerror( gaierr ) );
			socket_connect_bail( sock );
			return;
		}
		info( "\vok\n" );

		sock->curr_addr = sock->addrs;
#else
		struct hostent *he;

		infon( "Resolving %s... ", conf->host );
		he = gethostbyname( conf->host );
		if (!he) {
			error( "Error: Cannot resolve server '%s': %s\n", conf->host, hstrerror( h_errno ) );
			socket_connect_bail( sock );
			return;
		}
		info( "\vok\n" );

		sock->curr_addr = he->h_addr_list;
#endif
		socket_connect_one( sock );
	}
}

static void
socket_connect_one( conn_t *sock )
{
	int s;
#ifdef HAVE_IPV6
	struct addrinfo *ai;
#else
	struct {
		struct sockaddr_in ai_addr[1];
	} ai[1];
#endif

#ifdef HAVE_IPV6
	if (!(ai = sock->curr_addr)) {
#else
	if (!*sock->curr_addr) {
#endif
		error( "No working address found for %s\n", sock->conf->host );
		socket_connect_bail( sock );
		return;
	}

#ifdef HAVE_IPV6
	if (ai->ai_family == AF_INET6) {
		struct sockaddr_in6 *in6 = ((struct sockaddr_in6 *)ai->ai_addr);
		char sockname[64];
		in6->sin6_port = htons( sock->conf->port );
		nfasprintf( &sock->name, "%s ([%s]:%hu)",
		            sock->conf->host, inet_ntop( AF_INET6, &in6->sin6_addr, sockname, sizeof(sockname) ), sock->conf->port );
	} else
#endif
	{
		struct sockaddr_in *in = ((struct sockaddr_in *)ai->ai_addr);
#ifndef HAVE_IPV6
		memset( in, 0, sizeof(*in) );
		in->sin_family = AF_INET;
		in->sin_addr.s_addr = *((int *)*sock->curr_addr);
#endif
		in->sin_port = htons( sock->conf->port );
		nfasprintf( &sock->name, "%s (%s:%hu)",
		            sock->conf->host, inet_ntoa( in->sin_addr ), sock->conf->port );
	}

#ifdef HAVE_IPV6
	s = socket( ai->ai_family, SOCK_STREAM, 0 );
#else
	s = socket( PF_INET, SOCK_STREAM, 0 );
#endif
	if (s < 0) {
		socket_connect_next( sock );
		return;
	}
	socket_open_internal( sock, s );

	infon( "Connecting to %s... ", sock->name );
#ifdef HAVE_IPV6
	if (connect( s, ai->ai_addr, ai->ai_addrlen )) {
#else
	if (connect( s, ai->ai_addr, sizeof(*ai->ai_addr) )) {
#endif
		if (errno != EINPROGRESS) {
			socket_connect_failed( sock );
			return;
		}
		conf_notifier( &sock->notify, 0, POLLOUT );
		socket_expect_read( sock, 1 );
		sock->state = SCK_CONNECTING;
		info( "\v\n" );
		return;
	}
	info( "\vok\n" );
	socket_connected( sock );
}

static void
socket_connect_next( conn_t *conn )
{
	sys_error( "Cannot connect to %s", conn->name );
	free( conn->name );
	conn->name = 0;
#ifdef HAVE_IPV6
	conn->curr_addr = conn->curr_addr->ai_next;
#else
	conn->curr_addr++;
#endif
	socket_connect_one( conn );
}

static void
socket_connect_failed( conn_t *conn )
{
	socket_close_internal( conn );
	socket_connect_next( conn );
}

static void
socket_connected( conn_t *conn )
{
#ifdef HAVE_IPV6
	freeaddrinfo( conn->addrs );
	conn->addrs = 0;
#endif
	conf_notifier( &conn->notify, 0, POLLIN );
	socket_expect_read( conn, 0 );
	conn->state = SCK_READY;
	conn->callbacks.connect( 1, conn->callback_aux );
}

static void
socket_cleanup_names( conn_t *conn )
{
#ifdef HAVE_IPV6
	if (conn->addrs) {
		freeaddrinfo( conn->addrs );
		conn->addrs = 0;
	}
#endif
	free( conn->name );
	conn->name = 0;
}

static void
socket_connect_bail( conn_t *conn )
{
	socket_cleanup_names( conn );
	conn->callbacks.connect( 0, conn->callback_aux );
}

static void dispose_chunk( conn_t *conn );

void
socket_close( conn_t *sock )
{
	if (sock->fd >= 0)
		socket_close_internal( sock );
	socket_cleanup_names( sock );
#ifdef HAVE_LIBSSL
	if (sock->ssl) {
		SSL_free( sock->ssl );
		sock->ssl = 0;
		wipe_wakeup( &sock->ssl_fake );
	}
#endif
#ifdef HAVE_LIBZ
	if (sock->in_z) {
		inflateEnd( sock->in_z );
		free( sock->in_z );
		sock->in_z = 0;
		deflateEnd( sock->out_z );
		free( sock->out_z );
		sock->out_z = 0;
		wipe_wakeup( &sock->z_fake );
	}
#endif
	while (sock->write_buf)
		dispose_chunk( sock );
	free( sock->append_buf );
	sock->append_buf = 0;
}

static int
prepare_read( conn_t *sock, char **buf, int *len )
{
	int n = sock->offset + sock->bytes;
	if (!(*len = sizeof(sock->buf) - n)) {
		error( "Socket error: receive buffer full. Probably protocol error.\n" );
		socket_fail( sock );
		return -1;
	}
	*buf = sock->buf + n;
	return 0;
}

static int
do_read( conn_t *sock, char *buf, int len )
{
	int n;

	assert( sock->fd >= 0 );
	if (pending_wakeup( &sock->fd_timeout ))
		conf_wakeup( &sock->fd_timeout, sock->conf->timeout );
#ifdef HAVE_LIBSSL
	if (sock->ssl) {
		if ((n = ssl_return( "read from", sock, SSL_read( sock->ssl, buf, len ) )) <= 0)
			return n;

		if (n == len && SSL_pending( sock->ssl ))
			conf_wakeup( &sock->ssl_fake, 0 );
	} else
#endif
	{
		if ((n = read( sock->fd, buf, len )) < 0) {
			sys_error( "Socket error: read from %s", sock->name );
			socket_fail( sock );
		} else if (!n) {
			/* EOF. Callers take the short path out, so signal higher layers from here. */
			sock->state = SCK_EOF;
			sock->read_callback( sock->callback_aux );
		}
	}

	return n;
}

#ifdef HAVE_LIBZ
static void
socket_fill_z( conn_t *sock )
{
	char *buf;
	int len, ret;

	if (prepare_read( sock, &buf, &len ) < 0)
		return;

	sock->in_z->avail_out = len;
	sock->in_z->next_out = (unsigned char *)buf;

	ret = inflate( sock->in_z, Z_SYNC_FLUSH );
	/* Z_BUF_ERROR happens here when the previous call both consumed
	 * all input and exactly filled up the output buffer. */
	if (ret != Z_OK && ret != Z_BUF_ERROR && ret != Z_STREAM_END) {
		error( "Error decompressing data from %s: %s\n", sock->name, z_err_msg( ret, sock->in_z ) );
		socket_fail( sock );
		return;
	}

	if (!sock->in_z->avail_out)
		conf_wakeup( &sock->z_fake, 0 );

	if ((len = (char *)sock->in_z->next_out - buf)) {
		sock->bytes += len;
		sock->read_callback( sock->callback_aux );
	}
}
#endif

static void
socket_fill( conn_t *sock )
{
#ifdef HAVE_LIBZ
	if (sock->in_z) {
		int ret;
		/* The timer will preempt reads until the buffer is empty. */
		assert( !sock->in_z->avail_in );
		sock->in_z->next_in = (uchar *)sock->z_buf;
		if ((ret = do_read( sock, sock->z_buf, sizeof(sock->z_buf) )) <= 0)
			return;
		sock->in_z->avail_in = ret;
		socket_fill_z( sock );
	} else
#endif
	{
		char *buf;
		int len;

		if (prepare_read( sock, &buf, &len ) < 0)
			return;

		if ((len = do_read( sock, buf, len )) <= 0)
			return;

		sock->bytes += len;
		sock->read_callback( sock->callback_aux );
	}
}

void
socket_expect_read( conn_t *conn, int expect )
{
	if (conn->conf->timeout > 0 && expect != pending_wakeup( &conn->fd_timeout ))
		conf_wakeup( &conn->fd_timeout, expect ? conn->conf->timeout : -1 );
}

int
socket_read( conn_t *conn, char *buf, int len )
{
	int n = conn->bytes;
	if (!n && conn->state == SCK_EOF)
		return -1;
	if (n > len)
		n = len;
	memcpy( buf, conn->buf + conn->offset, n );
	if (!(conn->bytes -= n))
		conn->offset = 0;
	else
		conn->offset += n;
	return n;
}

char *
socket_read_line( conn_t *b )
{
	char *p, *s;
	int n;

	s = b->buf + b->offset;
	p = memchr( s + b->scanoff, '\n', b->bytes - b->scanoff );
	if (!p) {
		b->scanoff = b->bytes;
		if (b->offset + b->bytes == sizeof(b->buf)) {
			memmove( b->buf, b->buf + b->offset, b->bytes );
			b->offset = 0;
		}
		if (b->state == SCK_EOF)
			return (void *)~0;
		return 0;
	}
	n = p + 1 - s;
	b->offset += n;
	b->bytes -= n;
	b->scanoff = 0;
	if (p != s && p[-1] == '\r')
		p--;
	*p = 0;
	return s;
}

static int
do_write( conn_t *sock, char *buf, int len )
{
	int n;

	assert( sock->fd >= 0 );
#ifdef HAVE_LIBSSL
	if (sock->ssl)
		return ssl_return( "write to", sock, SSL_write( sock->ssl, buf, len ) );
#endif
	n = write( sock->fd, buf, len );
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			sys_error( "Socket error: write to %s", sock->name );
			socket_fail( sock );
		} else {
			n = 0;
			conf_notifier( &sock->notify, POLLIN, POLLOUT );
		}
	} else if (n != len) {
		conf_notifier( &sock->notify, POLLIN, POLLOUT );
	}
	return n;
}

static void
dispose_chunk( conn_t *conn )
{
	buff_chunk_t *bc = conn->write_buf;
	if (!(conn->write_buf = bc->next))
		conn->write_buf_append = &conn->write_buf;
	conn->buffer_mem -= bc->len;
	free( bc );
}

static int
do_queued_write( conn_t *conn )
{
	buff_chunk_t *bc;

	if (!conn->write_buf)
		return 0;

	while ((bc = conn->write_buf)) {
		int n, len = bc->len - conn->write_offset;
		if ((n = do_write( conn, bc->data + conn->write_offset, len )) < 0)
			return -1;
		if (n != len) {
			conn->write_offset += n;
			conn->writing = 1;
			return 0;
		}
		conn->write_offset = 0;
		dispose_chunk( conn );
	}
#ifdef HAVE_LIBSSL
	if (conn->ssl && SSL_pending( conn->ssl ))
		conf_wakeup( &conn->ssl_fake, 0 );
#endif
	conn->writing = 0;
	conn->write_callback( conn->callback_aux );
	return -1;
}

static void
do_append( conn_t *conn, buff_chunk_t *bc )
{
	bc->next = 0;
	conn->buffer_mem += bc->len;
	*conn->write_buf_append = bc;
	conn->write_buf_append = &bc->next;
}

/* This is big enough to avoid excessive chunking, but is
 * sufficiently small to keep SSL latency low with a slow uplink. */
#define WRITE_CHUNK_SIZE 1024

static void
do_flush( conn_t *conn )
{
	buff_chunk_t *bc = conn->append_buf;
#ifdef HAVE_LIBZ
	if (conn->out_z) {
		int buf_avail = conn->append_avail;
		if (!conn->z_written)
			return;
		do {
			int ret;
			if (!bc) {
				buf_avail = WRITE_CHUNK_SIZE;
				bc = nfmalloc( offsetof(buff_chunk_t, data) + buf_avail );
				bc->len = 0;
			}
			conn->out_z->next_in = Z_NULL;
			conn->out_z->avail_in = 0;
			conn->out_z->next_out = (uchar *)bc->data + bc->len;
			conn->out_z->avail_out = buf_avail;
			/* Z_BUF_ERROR cannot happen here, as zlib suppresses the error
			 * both upon increasing the flush level (1st iteration) and upon
			 * a no-op after the output buffer was full (later iterations). */
			if ((ret = deflate( conn->out_z, Z_PARTIAL_FLUSH )) != Z_OK) {
				error( "Fatal: Compression error: %s\n", z_err_msg( ret, conn->out_z ) );
				abort();
			}
			bc->len = (char *)conn->out_z->next_out - bc->data;
			if (bc->len) {
				do_append( conn, bc );
				bc = 0;
				buf_avail = 0;
			} else {
				buf_avail = conn->out_z->avail_out;
			}
		} while (!conn->out_z->avail_out);
		conn->append_buf = bc;
		conn->append_avail = buf_avail;
		conn->z_written = 0;
	} else
#endif
	if (bc) {
		do_append( conn, bc );
		conn->append_buf = 0;
#ifdef HAVE_LIBZ
		conn->append_avail = 0;
#endif
	}
}

void
socket_write( conn_t *conn, conn_iovec_t *iov, int iovcnt )
{
	int i, buf_avail, len, offset = 0, total = 0;
	buff_chunk_t *bc;

	for (i = 0; i < iovcnt; i++)
		total += iov[i].len;
	if (total >= WRITE_CHUNK_SIZE) {
		/* If the new data is too big, queue the pending buffer to avoid latency. */
		do_flush( conn );
	}
	bc = conn->append_buf;
#ifdef HAVE_LIBZ
	buf_avail = conn->append_avail;
#endif
	while (total) {
		if (!bc) {
			/* We don't do anything special when compressing, as there is no way to
			 * predict a reasonable output buffer size anyway - deflatePending() does
			 * not account for consumed but not yet compressed input, and adding up
			 * the deflateBound()s would be a tad *too* pessimistic. */
			buf_avail = total > WRITE_CHUNK_SIZE ? total : WRITE_CHUNK_SIZE;
			bc = nfmalloc( offsetof(buff_chunk_t, data) + buf_avail );
			bc->len = 0;
#ifndef HAVE_LIBZ
		} else {
			/* A pending buffer will always be of standard size - over-sized
			 * buffers are immediately filled and queued. */
			buf_avail = WRITE_CHUNK_SIZE - bc->len;
#endif
		}
		while (total) {
			len = iov->len - offset;
#ifdef HAVE_LIBZ
			if (conn->out_z) {
				int ret;
				conn->out_z->next_in = (uchar *)iov->buf + offset;
				conn->out_z->avail_in = len;
				conn->out_z->next_out = (uchar *)bc->data + bc->len;
				conn->out_z->avail_out = buf_avail;
				/* Z_BUF_ERROR is impossible here, as the input buffer always has data,
				 * and the output buffer always has space. */
				if ((ret = deflate( conn->out_z, Z_NO_FLUSH )) != Z_OK) {
					error( "Fatal: Compression error: %s\n", z_err_msg( ret, conn->out_z ) );
					abort();
				}
				bc->len = (char *)conn->out_z->next_out - bc->data;
				buf_avail = conn->out_z->avail_out;
				len -= conn->out_z->avail_in;
				conn->z_written = 1;
			} else
#endif
			{
				if (len > buf_avail)
					len = buf_avail;
				memcpy( bc->data + bc->len, iov->buf + offset, len );
				bc->len += len;
				buf_avail -= len;
			}
			offset += len;
			total -= len;
			if (offset == iov->len) {
				if (iov->takeOwn == GiveOwn)
					free( iov->buf );
				iov++;
				offset = 0;
			}
			if (!buf_avail) {
				do_append( conn, bc );
				bc = 0;
				break;
			}
		}
	}
	conn->append_buf = bc;
#ifdef HAVE_LIBZ
	conn->append_avail = buf_avail;
#endif
	conf_wakeup( &conn->fd_fake, 0 );
}

static void
socket_fd_cb( int events, void *aux )
{
	conn_t *conn = (conn_t *)aux;

	if ((events & POLLERR) || conn->state == SCK_CONNECTING) {
		int soerr;
		socklen_t selen = sizeof(soerr);
		if (getsockopt( conn->fd, SOL_SOCKET, SO_ERROR, &soerr, &selen )) {
			perror( "getsockopt" );
			exit( 1 );
		}
		errno = soerr;
		if (conn->state == SCK_CONNECTING) {
			if (errno)
				socket_connect_failed( conn );
			else
				socket_connected( conn );
			return;
		}
		sys_error( "Socket error from %s", conn->name );
		socket_fail( conn );
		return;
	}

	if (events & POLLOUT)
		conf_notifier( &conn->notify, POLLIN, 0 );

#ifdef HAVE_LIBSSL
	if (conn->state == SCK_STARTTLS) {
		start_tls_p2( conn );
		return;
	}
	if (conn->ssl) {
		if (do_queued_write( conn ) < 0)
			return;
		socket_fill( conn );
		return;
	}
#endif

	if ((events & POLLOUT) && do_queued_write( conn ) < 0)
		return;
	if (events & POLLIN)
		socket_fill( conn );
}

static void
socket_fake_cb( void *aux )
{
	conn_t *conn = (conn_t *)aux;

	/* Ensure that a pending write gets queued. */
	do_flush( conn );
	/* If no writes are ongoing, start writing now. */
	if (!conn->writing)
		do_queued_write( conn );
}

static void
socket_timeout_cb( void *aux )
{
	conn_t *conn = (conn_t *)aux;

	if (conn->state == SCK_CONNECTING) {
		errno = ETIMEDOUT;
		socket_connect_failed( conn );
	} else {
		error( "Socket error on %s: timeout.\n", conn->name );
		socket_fail( conn );
	}
}

#ifdef HAVE_LIBZ
static void
z_fake_cb( void *aux )
{
	conn_t *conn = (conn_t *)aux;

	socket_fill_z( conn );
}
#endif

#ifdef HAVE_LIBSSL
static void
ssl_fake_cb( void *aux )
{
	conn_t *conn = (conn_t *)aux;

	socket_fill( conn );
}
#endif
