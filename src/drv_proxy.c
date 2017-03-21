/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2017 Oswald Buddenhagen <ossi@users.sf.net>
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

#include <limits.h>
#include <stdlib.h>

typedef struct {
	store_t gen;
	const char *label; // foreign
	int ref_count;
	driver_t *real_driver;
	store_t *real_store;

	void (*bad_callback)( void *aux );
	void *bad_callback_aux;
} proxy_store_t;

static void ATTR_PRINTFLIKE(1, 2)
debug( const char *msg, ... )
{
	va_list va;

	va_start( va, msg );
	vdebug( DEBUG_DRV, msg, va );
	va_end( va );
}

static void ATTR_PRINTFLIKE(1, 2)
debugn( const char *msg, ... )
{
	va_list va;

	va_start( va, msg );
	vdebugn( DEBUG_DRV, msg, va );
	va_end( va );
}

static const char Flags[] = { 'D', 'F', 'R', 'S', 'T' };

static char *
proxy_make_flags( int flags, char *buf )
{
	uint i, d;

	for (d = 0, i = 0; i < as(Flags); i++)
		if (flags & (1 << i))
			buf[d++] = Flags[i];
	buf[d] = 0;
	return buf;
}

static void
proxy_store_deref( proxy_store_t *ctx )
{
	if (!--ctx->ref_count)
		free( ctx );
}

static int curr_tag;

typedef struct {
	int ref_count;
	int tag;
	proxy_store_t *ctx;
} gen_cmd_t;

static gen_cmd_t *
proxy_cmd_new( proxy_store_t *ctx, int sz )
{
	gen_cmd_t *cmd = nfmalloc( sz );
	cmd->ref_count = 2;
	cmd->tag = ++curr_tag;
	cmd->ctx = ctx;
	ctx->ref_count++;
	return cmd;
}

static void
proxy_cmd_done( gen_cmd_t *cmd )
{
	if (!--cmd->ref_count) {
		proxy_store_deref( cmd->ctx );
		free( cmd );
	}
}

#if 0
//# TEMPLATE GETTER
static @type@proxy_@name@( store_t *gctx )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	@type@rv = ctx->real_driver->@name@( ctx->real_store );
	debug( "%sCalled @name@, ret=@fmt@\n", ctx->label, rv );
	return rv;
}
//# END

//# TEMPLATE REGULAR
static @type@proxy_@name@( store_t *gctx@decl_args@ )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	@pre_print_args@
	debug( "%sEnter @name@@print_fmt_args@\n", ctx->label@print_pass_args@ );
	@print_args@
	@type@rv = ctx->real_driver->@name@( ctx->real_store@pass_args@ );
	debug( "%sLeave @name@, ret=@fmt@\n", ctx->label, rv );
	return rv;
}
//# END

//# TEMPLATE REGULAR_VOID
static void proxy_@name@( store_t *gctx@decl_args@ )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	@pre_print_args@
	debug( "%sEnter @name@@print_fmt_args@\n", ctx->label@print_pass_args@ );
	@print_args@
	ctx->real_driver->@name@( ctx->real_store@pass_args@ );
	debug( "%sLeave @name@\n", ctx->label );
	@action@
}
//# END

//# TEMPLATE CALLBACK
typedef struct {
	gen_cmd_t gen;
	void (*callback)( @decl_cb_args@void *aux );
	void *callback_aux;
	@decl_state@
} @name@_cmd_t;

static void
proxy_@name@_cb( @decl_cb_args@void *aux )
{
	@name@_cmd_t *cmd = (@name@_cmd_t *)aux;

	@pre_print_cb_args@
	debug( "%s[% 2d] Callback enter @name@@print_fmt_cb_args@\n", cmd->gen.ctx->label, cmd->gen.tag@print_pass_cb_args@ );
	@print_cb_args@
	cmd->callback( @pass_cb_args@cmd->callback_aux );
	debug( "%s[% 2d] Callback leave @name@\n", cmd->gen.ctx->label, cmd->gen.tag );
	proxy_cmd_done( &cmd->gen );
}

static void
proxy_@name@( store_t *gctx@decl_args@, void (*cb)( @decl_cb_args@void *aux ), void *aux )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	@name@_cmd_t *cmd = (@name@_cmd_t *)proxy_cmd_new( ctx, sizeof(@name@_cmd_t) );
	cmd->callback = cb;
	cmd->callback_aux = aux;
	@assign_state@
	@pre_print_args@
	debug( "%s[% 2d] Enter @name@@print_fmt_args@\n", ctx->label, cmd->gen.tag@print_pass_args@ );
	@print_args@
	ctx->real_driver->@name@( ctx->real_store@pass_args@, proxy_@name@_cb, cmd );
	debug( "%s[% 2d] Leave @name@\n", ctx->label, cmd->gen.tag );
	proxy_cmd_done( &cmd->gen );
}
//# END

//# UNDEFINE list_store_print_fmt_cb_args
//# UNDEFINE list_store_print_pass_cb_args
//# DEFINE list_store_print_cb_args
	if (sts == DRV_OK) {
		for (string_list_t *box = boxes; box; box = box->next)
			debug( "  %s\n", box->string );
	}
//# END

//# DEFINE load_box_pre_print_args
	static char ubuf[12];
//# END
//# DEFINE load_box_print_fmt_args , [%u,%s] (new >= %u, seen <= %u)
//# DEFINE load_box_print_pass_args , minuid, (maxuid == UINT_MAX) ? "inf" : (nfsnprintf( ubuf, sizeof(ubuf), "%u", maxuid ), ubuf), newuid, seenuid
//# DEFINE load_box_print_args
	if (excs.size) {
		debugn( "  excs:" );
		for (int t = 0; t < excs.size; t++)
			debugn( " %d", excs.data[t] );
		debug( "\n" );
	}
//# END
//# DEFINE load_box_pre_print_cb_args
	static char fbuf[as(Flags) + 1];
//# END
//# DEFINE load_box_print_fmt_cb_args , sts=%d, total=%d, recent=%d
//# DEFINE load_box_print_pass_cb_args , sts, total_msgs, recent_msgs
//# DEFINE load_box_print_cb_args
	if (sts == DRV_OK) {
		for (message_t *msg = msgs; msg; msg = msg->next)
			debug( "  uid=%5u, flags=%4s, size=%6d, tuid=%." stringify(TUIDL) "s\n",
			       msg->uid, (msg->status & M_FLAGS) ? (proxy_make_flags( msg->flags, fbuf ), fbuf) : "?", msg->size, *msg->tuid ? msg->tuid : "?" );
	}
//# END

//# DEFINE find_new_msgs_print_fmt_cb_args , sts=%d
//# DEFINE find_new_msgs_print_pass_cb_args , sts
//# DEFINE find_new_msgs_print_cb_args
	if (sts == DRV_OK) {
		for (message_t *msg = msgs; msg; msg = msg->next)
			debug( "  uid=%5u, tuid=%." stringify(TUIDL) "s\n", msg->uid, msg->tuid );
	}
//# END

//# DEFINE fetch_msg_decl_state
	msg_data_t *data;
//# END
//# DEFINE fetch_msg_assign_state
	cmd->data = data;
//# END
//# DEFINE fetch_msg_print_fmt_args , uid=%u, want_flags=%s, want_date=%s
//# DEFINE fetch_msg_print_pass_args , msg->uid, !(msg->status & M_FLAGS) ? "yes" : "no", data->date ? "yes" : "no"
//# DEFINE fetch_msg_pre_print_cb_args
	static char fbuf[as(Flags) + 1];
	proxy_make_flags( cmd->data->flags, fbuf );
//# END
//# DEFINE fetch_msg_print_fmt_cb_args , flags=%s, date=%ld, size=%d
//# DEFINE fetch_msg_print_pass_cb_args , fbuf, cmd->data->date, cmd->data->len
//# DEFINE fetch_msg_print_cb_args
	if (sts == DRV_OK && (DFlags & DEBUG_DRV_ALL)) {
		printf( "%s=========\n", cmd->gen.ctx->label );
		fwrite( cmd->data->data, cmd->data->len, 1, stdout );
		printf( "%s=========\n", cmd->gen.ctx->label );
		fflush( stdout );
	}
//# END

//# DEFINE store_msg_pre_print_args
	static char fbuf[as(Flags) + 1];
	proxy_make_flags( data->flags, fbuf );
//# END
//# DEFINE store_msg_print_fmt_args , flags=%s, date=%ld, size=%d, to_trash=%s
//# DEFINE store_msg_print_pass_args , fbuf, data->date, data->len, to_trash ? "yes" : "no"
//# DEFINE store_msg_print_args
	if (DFlags & DEBUG_DRV_ALL) {
		printf( "%s>>>>>>>>>\n", ctx->label );
		fwrite( data->data, data->len, 1, stdout );
		printf( "%s>>>>>>>>>\n", ctx->label );
		fflush( stdout );
	}
//# END

//# DEFINE set_msg_flags_pre_print_args
	static char fbuf1[as(Flags) + 1], fbuf2[as(Flags) + 1];
	proxy_make_flags( add, fbuf1 );
	proxy_make_flags( del, fbuf2 );
//# END
//# DEFINE set_msg_flags_print_fmt_args , uid=%u, add=%s, del=%s
//# DEFINE set_msg_flags_print_pass_args , uid, fbuf1, fbuf2

//# DEFINE trash_msg_print_fmt_args , uid=%u
//# DEFINE trash_msg_print_pass_args , msg->uid

//# DEFINE free_store_action
	proxy_store_deref( ctx );
//# END

//# DEFINE cancel_store_action
	proxy_store_deref( ctx );
//# END
#endif

//# SPECIAL commit_cmds
static void
proxy_commit_cmds( store_t *gctx )
{
	// Currently a dummy in all real drivers.
	(void) gctx;
}

//# SPECIAL set_bad_callback
static void
proxy_set_bad_callback( store_t *gctx, void (*cb)( void *aux ), void *aux )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	ctx->bad_callback = cb;
	ctx->bad_callback_aux = aux;
}

static void
proxy_invoke_bad_callback( proxy_store_t *ctx )
{
	debug( "%sCallback enter bad store\n", ctx->label );
	ctx->bad_callback( ctx->bad_callback_aux );
	debug( "%sCallback leave bad store\n", ctx->label ); \
}

//# EXCLUDE alloc_store
store_t *
proxy_alloc_store( store_t *real_ctx, const char *label )
{
	proxy_store_t *ctx;

	ctx = nfcalloc( sizeof(*ctx) );
	ctx->gen.driver = &proxy_driver;
	ctx->gen.conf = real_ctx->conf;
	ctx->ref_count = 1;
	ctx->label = label;
	ctx->real_driver = real_ctx->driver;
	ctx->real_store = real_ctx;
	ctx->real_driver->set_bad_callback( ctx->real_store, (void (*)(void *))proxy_invoke_bad_callback, ctx );
	return &ctx->gen;
}

//# EXCLUDE parse_store
//# EXCLUDE cleanup
//# EXCLUDE get_fail_state

#include "drv_proxy.inc"
