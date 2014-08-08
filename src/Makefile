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
CHARDEN		=	-fstack-protector -fPIC -D_FORTIFY_SOURCE=2 -O1
LHARDEN		=	-pie -fPIE
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(CHARDEN)
override LDFLAGS	+=	$(LIB) $(LHARDEN) -lpthread -lpolarssl

SOURCES		=	dislocker.c common.c config.c sectors.c \
			xstd/xstdio.c xstd/xstdlib.c \
			metadata/datums.c metadata/metadata.c metadata/vmk.c \
			metadata/fvek.c metadata/extended_info.c \
			metadata/guid.c metadata/print_metadata.c \
			accesses/rp/recovery_password.c accesses/stretch_key.c \
			accesses/user_pass/user_pass.c \
			accesses/bek/read_bekfile.c \
			encryption/decrypt.c encryption/encrypt.c \
			encryption/diffuser.c encryption/crc32.c \
			ntfs/clock.c ntfs/encoding.c \
			outputs/prepare.c
OBJECTS		=	$(SOURCES:.c=.o)

BIN		=	$(PROGNAME)


INSTALL_PATH	=	$(DESTDIR)/usr/bin/

MAN_NUMBER	=	1
MAN_PATH	=	$(DESTDIR)/usr/share/man/man$(MAN_NUMBER)/
MAN_ROOT	=	../man/

FUSE_ROOT	:=	outputs/fuse/fuse
FILE_ROOT	:=	outputs/file/file



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

.PHONY : all libs static $(BIN) file fuse common clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : fuse

libs: $(OBJECTS)
	@# Nothing to do here

# Default rules for final binaries
touch :
	touch $(BIN).c

$(BIN) : touch libs
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)


static : touch libs
	$(CC) -static  $(CFLAGS) -o $(BIN)-static $(OBJECTS) $(LDFLAGS) -lz -ldl


# Build the binary for the file output
file: CFLAGS  += -D__RUN_FILE
file: SOURCES += $(FILE_ROOT).c
file: $(FILE_ROOT).o

file: $(BIN)


# Build the binary for the fuse output
fuse: CFLAGS  += -D__RUN_FUSE -DFUSE_USE_VERSION=26
fuse: SOURCES += $(FUSE_ROOT).c

# Don't link with the same library on MacOSX
ifeq ($(OS), Darwin)
fuse: LDFLAGS += -losxfuse_i64
else
fuse: LDFLAGS += -lfuse
endif # Darwin

fuse: $(FUSE_ROOT).o

fuse: $(BIN)


# Check if the installed binary is present, make it if it isn't
check-install :
	@[ -e $(BIN) ] && echo "Found $(BIN) binary, installing it" || make clean fuse

# Classic rules
common : common.o xstd/xstdio.o xstd/xstdlib.o metadata/datums.o metadata/print_metadata.o metadata/extended_info.o
	@$(MAKE) -C ntfs/

install: check-install
	install -pm755 $(BIN) $(INSTALL_PATH)$(BIN)
	if [ "$(OS)" = "Darwin" ]; then                                       \
		cp $(MAN_ROOT)$(BIN)_osx_man $(MAN_ROOT)$(BIN).$(MAN_NUMBER); \
	else                                                                  \
		cp $(MAN_ROOT)$(BIN)_man $(MAN_ROOT)$(BIN).$(MAN_NUMBER);     \
	fi
	gzip $(MAN_ROOT)$(BIN).$(MAN_NUMBER)
	mv $(MAN_ROOT)$(BIN).$(MAN_NUMBER).gz $(MAN_PATH)
	@echo "==========================================================="
	@echo "'$(BIN)' installed into" $(INSTALL_PATH)
	@echo "See 'man 1 $(BIN)' for details on how to use it"

uninstall: clean
	[ -f $(INSTALL_PATH)$(BIN) ]              && rm $(INSTALL_PATH)$(BIN)
	[ -f $(MAN_PATH)$(BIN).$(MAN_NUMBER).gz ] && rm $(MAN_PATH)$(BIN).$(MAN_NUMBER).gz
	@echo "==========================================================="
	@echo "$(BIN) uninstalled"


clean:
	rm -rf -- $(OBJECTS) $(FILE_ROOT).o $(FUSE_ROOT).o *~ *.swp $(BIN)

valgrind: clean $(BIN)
	valgrind --leak-check=full --show-reachable=yes ./$(BIN) $(ARGS)

snapshot: clean
	cd .. && (git status | grep -q 'nothing to commit' || git commit -a -m 'Snapshot v$(VERSION)') && git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD | gzip > /tmp/$(BIN)-$(DATE).tar.gz

release: clean
	cd .. && (git status | grep -q 'nothing to commit' || git commit -a) && git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD | gzip > /tmp/$(BIN)-$(VERSION).tar.gz

