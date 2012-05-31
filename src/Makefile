BINDIR =	/usr/sbin
MANDIR =	/usr/man/man8
#CC =		gcc
DEFINES =	
INCDIRS =	
LIBDIRS =	
CFLAGS =	-Wall $(DEFINES) $(INCDIRS)
LDFLAGS =	-g3 $(LIBDIRS)
INSTALL =	/usr/bin/install

all:			srs-filter

srs-filter:		srs-filter.o
	$(CC) $(LDFLAGS) srs-filter.o -lmilter -lpthread -lspf2 -lsrs2 -o srs-filter
#	$(CC) $(LDFLAGS) srs-filter.o -lmilter -lpthread -lspf2 -lsrs2 -ldb -o srs-filter

.c.o:
	$(CC) $(CFLAGS) -c $<

srs-filter.o:	srs-filter.c


install:		all
	$(INSTALL) -c srs-filter $(BINDIR)/srs-filter
#	$(INSTALL) -c -m 644 srs-filter.8 $(MANDIR)/srs-filter.8

clean:
	rm -f srs-filter *.o a.out core
