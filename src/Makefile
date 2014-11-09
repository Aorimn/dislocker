PROGNAME	=	dislocker
AUTHOR		=	\"Romain Coltel\"
VERSION		=	0.3.1
ARCH		=	$(shell uname -m)
OS		=	$(shell uname -s)
DATE		=	$(shell date +%Y-%m-%d)

# DEBUG		=	1

ifeq ($(OS), FreeBSD)
MAKE		=	gmake
else
MAKE		=	make
endif


CC		=	cc
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\" -DVERSION=\"$(VERSION)\" -D_FILE_OFFSET_BITS=64
DEFINES		+=	-DAUTHOR="$(AUTHOR)" -D__OS=\"$(OS)\" -D__ARCH=\"$(ARCH)\"
DEFINES		+=	-D__ARCH_$(shell echo $(ARCH) | tr a-z A-Z) -D__$(shell echo $(OS) | tr a-z A-Z)
INC		=	-I. -I/usr/local/include
LIB		=	-l$(PROGNAME) -lpthread -lpolarssl -L.
CHARDEN		=	-fstack-protector -fPIC -D_FORTIFY_SOURCE=2 -O1
LHARDEN		=	-pie -fPIE
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(CHARDEN)
override LDFLAGS +=	$(LIB) $(LHARDEN)
LIBNAME		=	lib$(PROGNAME).so

BIN		=	$(PROGNAME)
SUFFIXES	=	fuse file metadata bek
BINS		=	$(foreach suf, $(SUFFIXES), $(BIN)-$(suf))
BINS_OBJECTS	=	$(foreach bin, $(BINS), $(bin).o)

SOURCES		=	dislocker.c common.c config.c sectors.c \
			xstd/xstdio.c xstd/xstdlib.c \
			metadata/datums.c metadata/metadata.c metadata/vmk.c \
			metadata/fvek.c metadata/extended_info.c \
			metadata/guid.c metadata/print_metadata.c \
			accesses/rp/recovery_password.c accesses/stretch_key.c \
			accesses/user_pass/user_pass.c accesses/bek/bekfile.c \
			accesses/accesses.c \
			encryption/decrypt.c encryption/encrypt.c \
			encryption/diffuser.c encryption/crc32.c \
			ntfs/clock.c ntfs/encoding.c \
			outputs/prepare.c
OBJECTS		=	$(SOURCES:.c=.o)



DESTDIR		=	/usr

BINARIES_PATH	=	$(DESTDIR)/bin/
LIBRARY_PATH	=	$(DESTDIR)/lib/

MAN_NUMBER	=	1
MAN_PATH	=	$(DESTDIR)/share/man/man$(MAN_NUMBER)/
MAN_ROOT	=	../man/




# For MacOSX users
ifneq ($(OS), Darwin)
# Useless warnings when used within Darwin
WFLAGS		+=	-Wconversion
# FIXME wtf with ld on OSX?
LHARDEN		+=	-Wl,-z,relro -Wl,-z,now
endif

ifeq ($(OS), FreeBSD)
LIB		+=	-L/usr/local/lib
endif

ifeq ($(CC), clang)
WFLAGS		+=	 -Qunused-arguments
endif

ifdef DEBUG
DBGFLAGS	=	-ggdb -D DEBUG=$(DEBUG)
CFLAGS		+=	$(DBGFLAGS)
endif



export

.PHONY : all libs $(BIN) $(SUFFIXES) install uninstall clean travis-install valgrind snapshot release

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

libs: $(OBJECTS)
	$(CC) -shared $(CFLAGS) -o $(LIBNAME) $(OBJECTS)

# Default rules for final binaries
$(BIN) : libs $(SUFFIXES)


# Build the binary for the file output
file: libs $(BIN)-file.o
	$(CC) $(CFLAGS) -o $(BIN)-file $(BIN)-file.o $(LDFLAGS)

# Build the binary for the fuse output
fuse: CFLAGS  += -DFUSE_USE_VERSION=26

# Don't link with the same library on MacOSX
ifeq ($(OS), Darwin)
fuse: LDFLAGS += -losxfuse_i64
else
fuse: LDFLAGS += -lfuse
endif # Darwin

fuse: libs $(BIN)-fuse.o
	$(CC) $(CFLAGS) -o $(BIN)-fuse $(BIN)-fuse.o $(LDFLAGS)


# Build the binary for getting metadata only
metadata: libs $(BIN)-metadata.o
	$(CC) $(CFLAGS) -o $(BIN)-metadata $(BIN)-metadata.o $(LDFLAGS)

# Build the binary for getting bek information only
bek: libs $(BIN)-bek.o
	$(CC) $(CFLAGS) -o $(BIN)-bek $(BIN)-bek.o $(LDFLAGS)



install: all
	install -pm755 $(BINS) $(BINARIES_PATH)
	ln -s $(BIN)-fuse $(BINARIES_PATH)$(BIN)
	install -pm755 $(LIBNAME) $(LIBRARY_PATH)
	if [ "$(OS)" = "Darwin" ]; then                                       \
		cp $(MAN_ROOT)$(BIN)_osx_man $(MAN_ROOT)$(BIN).$(MAN_NUMBER); \
	else                                                                  \
		cp $(MAN_ROOT)$(BIN)_man $(MAN_ROOT)$(BIN).$(MAN_NUMBER);     \
	fi
	gzip $(MAN_ROOT)$(BIN).$(MAN_NUMBER)
	mv $(MAN_ROOT)$(BIN).$(MAN_NUMBER).gz $(MAN_PATH)
	@echo "==========================================================="
	@echo "'$(BIN)' installed into" $(BINARIES_PATH)
	@echo "See 'man 1 $(BIN)' for details on how to use it"

uninstall: clean
	if [ -f $(BINARIES_PATH)$(BIN) ]; then rm $(BINARIES_PATH)$(BIN); fi
	for prog in $(BINS); do \
		if [ -f $(BINARIES_PATH)$${prog} ]; then rm $(BINARIES_PATH)$${prog}; fi \
	done
	if [ -f $(LIBRARY_PATH)$(LIBNAME) ]; then          rm $(LIBRARY_PATH)$(LIBNAME); fi
	if [ -f $(MAN_PATH)$(BIN).$(MAN_NUMBER).gz ]; then rm $(MAN_PATH)$(BIN).$(MAN_NUMBER).gz; fi
	@echo "==========================================================="
	@echo "$(BIN) uninstalled"


clean:
	rm -rf -- $(OBJECTS) *~ *.swp $(BINS) $(BINS_OBJECTS) $(LIBNAME)

travis-install:
	if [ "$$TRAVIS_OS_NAME" = "linux" ]; then                     \
		sudo apt-get update -qq;                              \
		sudo apt-get install -qq libfuse-dev libpolarssl-dev; \
		make CC=$$CC;                                         \
		sudo make install;                                    \
	elif [ "$$TRAVIS_OS_NAME" = "osx" ]; then                     \
		brew update;                                          \
		brew install dislocker.rb;                            \
	fi

travis-test:
	@echo "Testing dislocker..."
	dislocker -h
	for prog in $(BINS); do             \
		echo "Testing $${prog}..."; \
		$${prog} -h;                \
	done

valgrind: clean $(BIN)
	valgrind --leak-check=full --show-reachable=yes ./$(BIN) $(ARGS)

snapshot: clean
	cd .. && (git status | grep -q 'nothing to commit' || git commit -a -m 'Snapshot v$(VERSION)') && git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD | gzip > /tmp/$(BIN)-$(DATE).tar.gz

release: clean
	cd .. && (git status | grep -q 'nothing to commit' || git commit -a) && git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD | gzip > /tmp/$(BIN)-$(VERSION).tar.gz

