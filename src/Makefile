PROGNAME	=	dislocker
AUTHOR		=	\"Romain Coltel\"
VERSION_MAJOR	=	0
VERSION_MINOR	=	4
VERSION_RELEASE	=	1
VERSION		=	$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_RELEASE)
ARCH		=	$(shell uname -m)
OS		=	$(shell uname -s)
DATE		=	$(shell date +%Y-%m-%d)

# DEBUG		=	1


# Note that some variables here are changed below depending on the environment
# this file is run in
CC		=	cc
INSTALL		=	install

DEFINES		=	-DPROGNAME=\"$(PROGNAME)\" -DVERSION=\"$(VERSION)\" -D_FILE_OFFSET_BITS=64
DEFINES		+=	-DAUTHOR="$(AUTHOR)" -D__OS=\"$(OS)\" -D__ARCH=\"$(ARCH)\"
DEFINES		+=	-D__ARCH_$(shell echo $(ARCH) | tr a-z A-Z) -D__$(shell echo $(OS) | tr a-z A-Z)
INC		=	-I. -I/usr/local/include
LIB		=	-lpthread -lpolarssl -L. -L/usr/local/lib
CHARDEN		=	-fstack-protector -fPIC -D_FORTIFY_SOURCE=2 -O1
LHARDEN		=	-pie -fPIE
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		+=	$(WFLAGS) $(DEFINES) $(INC) $(CHARDEN)
LDFLAGS 	+=	-l$(PROGNAME) $(LIB) $(LHARDEN)
LINKERNAME	:=	lib$(PROGNAME).so
SONAME		:=	$(LINKERNAME).$(VERSION_MAJOR)
LIBNAME		:=	$(LINKERNAME).$(VERSION)
SHARED_FLAGS	=	-shared -Wl,-soname,$(SONAME)

BIN		=	$(PROGNAME)
SUFFIXES	=	fuse file metadata bek
BINS		=	$(foreach suf, $(SUFFIXES), $(BIN)-$(suf))
BINS_OBJECTS	=	$(foreach bin, $(BINS), $(bin).o)
DEFAULT_PROG	=	$(word 1, $(BINS))

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


DESTDIR		=
prefix		=	/usr

bindir		=	$(DESTDIR)$(prefix)/bin/
libdir		=	$(DESTDIR)$(prefix)/lib/
# Change library path for OS which have a lib64/ directory as ld's looking into
# it while loading the library instead of lib/
ifneq ("$(wildcard $(DESTDIR)$(prefix)/lib64/)", "")
libdir		=	$(DESTDIR)$(prefix)/lib64/
endif

mandir		:=	$(DESTDIR)$(prefix)/share/man/
man1dir		:=	$(mandir)man1/
man3dir		:=	$(mandir)man3/
man1ext		:=	.1
man3ext		:=	.3
mansrcdir	:=	../man/$(shell echo $(OS) | tr A-Z a-z)/
# Get manpages only if the binary is to be installed
man1pages	:=	$(wildcard $(foreach bin, $(BINS), $(mansrcdir)$(bin)$(man1ext)))
# man3pages	:=	$(wildcard $(mansrcdir)*$(man3ext))
man1pagesgz	:=	$(patsubst %$(man1ext), %$(man1ext).gz, $(man1pages))
man3pagesgz	:=	$(patsubst %$(man3ext), %$(man3ext).gz, $(man3pages))
manpages	:=	$(man1pages) $(man3pages)
manpagesgz	:=	$(man1pagesgz) $(man3pagesgz)
DEFAULT_MAN	:=	$(word 1, $(BINS))$(man1ext)



# For MacOSX users, some parameters change
ifeq ($(OS), Darwin)
# Force clang on OSX
override CC	=	clang
# Don't use `-read_only_relocs' here as it seems to only work for 32 bits
# binaries
LHARDEN		+=	-Wl,-bind_at_load
# Change every flag for generating dynamic shared object under OSX
LINKERNAME	=	lib$(PROGNAME).dylib
SONAME		=	$(LINKERNAME).$(VERSION_MAJOR)
LIBNAME		=	lib$(PROGNAME).$(VERSION_MAJOR).dylib
SHARED_FLAGS	=	-dynamiclib -current_version $(VERSION_MAJOR).$(VERSION_MINOR) -compatibility_version $(VERSION_MAJOR).$(VERSION_MINOR)
else
# Useless warnings when used within Darwin
WFLAGS		+=	-Wconversion
endif # Darwin


ifeq ($(CC), clang)
WFLAGS		+=	 -Qunused-arguments
endif


# These flags seem to be GNU ld specifics, cf above for OSX flags
ifeq ("$(shell ld --version 2>/dev/null | grep -o GNU | head -n 1)", "GNU")
LHARDEN		+=	-Wl,-z,now -Wl,-z,relro
endif


ifdef DEBUG
DBGFLAGS	=	-ggdb -D DEBUG=$(DEBUG)
CFLAGS		+=	$(DBGFLAGS)
endif



export

.PHONY : all $(BIN) install-bins install-lib install-man install uninstall-bins uninstall-lib uninstall-man uninstall clean travis-install travis-test valgrind snapshot release
.SUFFIXES :
.SUFFIXES : .c .o .gz

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<
%.gz : %
	gzip -c $< > $@

all : $(BIN) $(manpagesgz)

lib: $(LIBNAME)
$(LIBNAME): $(OBJECTS)
	$(CC) $(SHARED_FLAGS) $(CFLAGS) -o $(LIBNAME) $(OBJECTS) $(LIB)
	rm -f $(SONAME) $(LINKERNAME)
	ln -s $(LIBNAME) $(SONAME)
	ln -s $(SONAME) $(LINKERNAME)

# Default rules for final binaries
$(BIN): $(LIBNAME) $(BINS)


# Build the binary for the file output
$(BIN)-file: $(LIBNAME) $(BIN)-file.o
	$(CC) $(CFLAGS) -o $@ $@.o $(LDFLAGS)

# Build the binary for the fuse output
$(BIN)-fuse: CFLAGS  += -DFUSE_USE_VERSION=26

# Don't link with the same library on MacOSX
ifeq ($(OS), Darwin)
$(BIN)-fuse: LDFLAGS += -losxfuse_i64
else
$(BIN)-fuse: LDFLAGS += -lfuse
endif # Darwin

$(BIN)-fuse: $(LIBNAME) $(BIN)-fuse.o
	$(CC) $(CFLAGS) -o $@ $@.o $(LDFLAGS)


# Build the binary for getting metadata only
$(BIN)-metadata: $(LIBNAME) $(BIN)-metadata.o
	$(CC) $(CFLAGS) -o $@ $@.o $(LDFLAGS)

# Build the binary for getting bek information only
$(BIN)-bek: $(LIBNAME) $(BIN)-bek.o
	$(CC) $(CFLAGS) -o $@ $@.o $(LDFLAGS)


install-bins:
	$(INSTALL) -p -m 755 $(BINS) $(bindir)
	ln -s $(DEFAULT_PROG) $(bindir)$(BIN)
install-lib:
	$(INSTALL) -p -m 755 $(LIBNAME) $(libdir)
	cd $(libdir) && ln -s $(LIBNAME) $(SONAME)
	cd $(libdir) && ln -s $(SONAME) $(LINKERNAME)
install-man:
	$(INSTALL) -p -m 644 $(man1pagesgz) $(man1dir)
	ln -s $(DEFAULT_MAN).gz $(man1dir)$(BIN)$(man1ext).gz
# 	$(INSTALL) -p -m 644 $(man3pagesgz) $(man3dir)
install: all install-bins install-lib install-man
	@echo "==========================================================="
	@echo "'$(BIN)' installed into" $(bindir)
	@echo "'$(SONAME)' installed into" $(libdir)
	@echo "See 'man 1 $(BIN)' for details on how to use it"

uninstall-bins:
	if [ -f $(bindir)$(BIN) ]; then rm $(bindir)$(BIN); fi
	for prog in $(BINS); do \
		if [ -f $(bindir)$${prog} ]; then rm $(bindir)$${prog}; fi \
	done
uninstall-lib:
	if [ -f $(libdir)$(LINKERNAME) ]; then rm $(libdir)$(LINKERNAME); fi
	if [ -f $(libdir)$(SONAME) ]; then     rm $(libdir)$(SONAME); fi
	if [ -f $(libdir)$(LIBNAME) ]; then    rm $(libdir)$(LIBNAME); fi
uninstall-man:
	if [ -f $(man1dir)$(BIN)$(man1ext).gz ]; then rm $(man1dir)$(BIN)$(man1ext).gz; fi
	for manpagegz in $(notdir $(man1pagesgz)); do \
		if [ -f $(man1dir)$$manpagegz ]; then rm $(man1dir)$$manpagegz; fi; \
	done
	for manpagegz in $(notdir $(man3pagesgz)); do \
		if [ -f $(man3dir)$$manpagegz ]; then rm $(man3dir)$$manpagegz; fi; \
	done
uninstall: clean uninstall-bins uninstall-lib uninstall-man
	@echo "==========================================================="
	@echo "$(BIN) uninstalled"


clean:
	rm -rf -- $(OBJECTS) *~ *.swp $(BINS) $(BINS_OBJECTS) $(LIBNAME) $(SONAME) $(LINKERNAME) $(manpagesgz)

travis-install:
	if [ "$$TRAVIS_OS_NAME" = "linux" ]; then                     \
		sudo apt-get update -qq;                              \
		sudo apt-get install -qq libfuse-dev libpolarssl-dev; \
	elif [ "$$TRAVIS_OS_NAME" = "osx" ]; then                     \
		brew update;                                          \
		brew install polarssl;                                \
		brew install osxfuse;                                 \
	fi
	make CC=$(CC)
	sudo make CC=$(CC) install

travis-test:
	@echo "Testing dislocker..."
	dislocker -h
	for prog in $(BINS); do             \
		echo "Testing $${prog}..."; \
		$${prog} -h;                \
	done
	@echo "Looking for dislocker's manual..."
	man -w dislocker

valgrind: clean $(BIN)
	valgrind --leak-check=full --show-reachable=yes ./$(BIN) $(ARGS)

snapshot: clean
	cd .. && git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD | gzip > /tmp/$(BIN)-$(DATE).tar.gz

release: clean
	cd .. && (git status | grep -q 'nothing to commit' || git commit -a) && git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD | gzip > /tmp/$(BIN)-$(VERSION).tar.gz

