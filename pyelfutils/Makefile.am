## Process this file with automake to create Makefile.in
##
## Copyright (C) 1996-2010 Red Hat, Inc.
## This file is part of Red Hat elfutils.
##
## Red Hat elfutils is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by the
## Free Software Foundation; version 2 of the License.
##
## Red Hat elfutils is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with Red Hat elfutils; if not, write to the Free Software Foundation,
## Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301 USA.
##
## Red Hat elfutils is an included package of the Open Invention Network.
## An included package of the Open Invention Network is a package for which
## Open Invention Network licensees cross-license their patents.  No patent
## license is granted, either expressly or impliedly, by designation as an
## included package.  Should you wish to participate in the Open Invention
## Network licensing program, please visit www.openinventionnetwork.com
## <http://www.openinventionnetwork.com>.
##
include $(top_srcdir)/config/eu.am
AM_CFLAGS += -pthread -fno-strict-aliasing -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -mtune=generic -D_GNU_SOURCE -fPIC -fwrapv -DNDEBUG \
	    -I$(srcdir)/../libelf -I$(srcdir)/../libebl \
	    -I$(srcdir)/../libdw -I$(srcdir)/../libdwfl -I$(top_srcdir)/lib \
	    -I$(srcdir)/../libasm -I/usr/include/python2.7 -I$(top_srcdir)
VERSION = 1

if BUILD_STATIC
libasm = ../libasm/libasm.a
libdw = ../libdw/libdw.a $(zip_LIBS) $(libelf) $(libebl) -ldl
libelf = ../libelf/libelf.a
else
libasm = ../libasm/libasm.so
libdw = ../libdw/libdw.so
libelf = ../libelf/libelf.so
endif
libebl = ../libebl/libebl.a
libeu = ../lib/libeu.a

all: elfutils.so

elfutils_so_LDLIBS = $(libdw)  $(libelf) $(libmudflap) -ldl -lpython2.7 

elfutils.o:elfutils.c
	$(CC) -o $@ -c $(AM_CFLAGS) $^

elfutils.so: elfutils.o
	$(CC) -o $@ -shared $(elfutils_so_LDLIBS) elfutils.o $(libebl) $(libeu) 

install: install-am elfutils.so
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	$(INSTALL_PROGRAM) elfutils.so $(DESTDIR)$(libdir)/elfutils.so

uninstall: uninstall-am
	rm -f $(DESTDIR)$(libdir)/elfutils.so

CLEANFILES += $(am_elfutils_pic_a_OBJECTS) elfutils.so
