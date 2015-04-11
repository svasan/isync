if with_compat
compat_dir = compat
endif
SUBDIRS = $(compat_dir)

mbsync_SOURCES = main.c sync.c config.c util.c socket.c driver.c drv_imap.c drv_maildir.c
mbsync_LDADD = $(DB_LIBS) $(SSL_LIBS) $(SOCK_LIBS) $(SASL_LIBS) $(Z_LIBS)
noinst_HEADERS = common.h config.h driver.h sync.h socket.h

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

EXTRA_DIST = run-tests.pl $(example_DATA) $(man_MANS)
