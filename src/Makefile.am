if with_compat
compat_dir = compat
endif
SUBDIRS = $(compat_dir)

mbsync_SOURCES = main.c sync.c config.c util.c socket.c driver.c drv_imap.c drv_maildir.c drv_proxy.c
mbsync_LDADD = $(DB_LIBS) $(SSL_LIBS) $(SOCK_LIBS) $(SASL_LIBS) $(Z_LIBS)
noinst_HEADERS = common.h config.h driver.h sync.h socket.h

drv_proxy.$(OBJEXT): drv_proxy.inc
drv_proxy.inc: $(srcdir)/driver.h $(srcdir)/drv_proxy.c $(srcdir)/drv_proxy_gen.pl
	perl $(srcdir)/drv_proxy_gen.pl $(srcdir)/driver.h $(srcdir)/drv_proxy.c drv_proxy.inc

mdconvert_SOURCES = mdconvert.c
mdconvert_LDADD = $(DB_LIBS)
if with_mdconvert
mdconvert_prog = mdconvert
mdconvert_man = mdconvert.1
endif

EXTRA_PROGRAMS = tst_timers

tst_timers_SOURCES = tst_timers.c util.c

bin_PROGRAMS = mbsync $(mdconvert_prog)
man_MANS = mbsync.1 $(mdconvert_man)

exampledir = $(docdir)/examples
example_DATA = mbsyncrc.sample

EXTRA_DIST = drv_proxy_gen.pl run-tests.pl $(example_DATA) $(man_MANS)

CLEANFILES = drv_proxy.inc
