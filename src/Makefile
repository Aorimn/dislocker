PROGNAME	=	dislocker
AUTHOR		=	\"Romain Coltel\"
VERSION		=	0.3
ARCH		=	$(shell uname)
DATE		=	$(shell date +%Y-%m-%d)

# DEBUG		=	1


# Choose between one of them (done automatically by using `make fuse' or `make file')
__RUN_FUSE	=	0
__RUN_FILE	=	0
# NOTE: __RUN_FILE can be a veeeeeeeery long process to complete


CC		=	gcc
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\" -DVERSION=\"$(VERSION)\" -D_FILE_OFFSET_BITS=64
INC		=	-I/usr/include -I.
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(LIB)
SOURCES		=	dislocker.c common.c sectors.c \
			config.c xstd/xstdio.c xstd/xstdlib.c
OBJECTS		=	$(SOURCES:.c=.o)
LDFLAGS		=	-lpthread
BIN		=	$(PROGNAME)

EXT_OBJ		=	metadata/datums.o metadata/metadata.o metadata/vmk.o metadata/fvek.o metadata/extended_info.o \
			accesses/rp/recovery_password.o accesses/bek/read_bekfile.o \
			accesses/user_pass/user_pass.o accesses/stretch_key.o \
			encryption/decrypt.o encryption/encrypt.o encryption/diffuser.o encryption/crc32.o \
			ntfs/guid.o ntfs/clock.o ntfs/encoding.o \
			polarssl/aes.o polarssl/sha2.o


INSTALL_PATH	=	/usr/bin/

MAN_NUMBER	=	1
MAN_PATH	=	/usr/share/man/man$(MAN_NUMBER)/
MAN_ROOT	=	../man/

FUSE_ROOT	=	outputs/fuse/fuse
FILE_ROOT	=	outputs/file/file


# Get the system architecture
ifeq ($(shell uname -m), x86_64)
LIB		=	-L/usr/lib64
CFLAGS		+=	-D__ARCH_X86_64
else
LIB		=	-L/usr/lib
endif


# For MacOSX users
ifeq ($(shell uname -s), Darwin)
DEFINES		+=	-D__DARWIN
else
# Useless warnings when used within Darwin
WFLAGS		+=	-Wconversion
endif





ifdef DEBUG
DBGFLAGS	=	-ggdb -D DEBUG=$(DEBUG)
CFLAGS		+=	$(DBGFLAGS)
endif





.PHONY : all libs static $(BIN) file fuse common clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : fuse

libs: $(OBJECTS)
	@make DEBUG=$(DEBUG) -C polarssl/   library
	@make DEBUG=$(DEBUG) -C accesses/   library
	@make DEBUG=$(DEBUG) -C metadata/   library
	@make DEBUG=$(DEBUG) -C ntfs/       library
	@make DEBUG=$(DEBUG) -C encryption/ library


# Default rules for final binaries
$(BIN) : libs
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(EXT_OBJ) $(LDFLAGS)


static : libs
	$(CC) -static  $(CFLAGS) -o $(BIN)-static $(OBJECTS) $(EXT_OBJ) $(LDFLAGS) -lz -ldl 


# Build the binary for the file output
file: CFLAGS  += -D__RUN_FILE
file: SOURCES += $(FILE_ROOT).c
file: $(FILE_ROOT).o

file: $(BIN)


# Build the binary for the fuse output
fuse: CFLAGS  += -D__RUN_FUSE -DFUSE_USE_VERSION=26
fuse: SOURCES += $(FUSE_ROOT).c

# Don't link with the same library on MacOSX
ifeq ($(shell uname -s), Darwin)
fuse: LDFLAGS += -losxfuse_i64
else
fuse: LDFLAGS += -lfuse
endif # Darwin

fuse: $(FUSE_ROOT).o

fuse: $(BIN)


# Classic rules
common : common.o xstd/xstdio.o xstd/xstdlib.o metadata/datums.o
	@make -C ntfs/

install: all
	cp $(BIN) $(INSTALL_PATH)
	chmod 755 $(INSTALL_PATH)$(BIN)
	cp $(MAN_ROOT)$(BIN)_man $(MAN_ROOT)$(BIN).$(MAN_NUMBER)
	gzip $(MAN_ROOT)$(BIN).$(MAN_NUMBER)
	mv $(MAN_ROOT)$(BIN).$(MAN_NUMBER).gz $(MAN_PATH)
	@echo "==========================================================="
	@echo "'$(BIN)' installed into" $(INSTALL_PATH)
	@echo "See 'man 1 $(BIN)' for details on how to use it"

uninstall: clean
	[ -f $(INSTALL_PATH)$(BIN) ] && rm $(INSTALL_PATH)$(BIN)           || echo -n ""
	[ -f $(INSTALL_PATH)$(BIN) ] && rm $(MAN_PATH)$(BIN).$(MAN_NUMBER) || echo -n ""
	[ -f $(MAN_ROOT)$(BIN).$(MAN_NUMBER).gz && rm $(MAN_ROOT)$(BIN).$(MAN_NUMBER).gz ] || echo -n ""
	@echo "==========================================================="
	@echo "$(BIN) uninstalled"


clean:
	$(eval SOURCES += $(FILE_ROOT).c)
	$(eval SOURCES += $(FUSE_ROOT).c)
	rm -rf -- $(EXT_OBJ) $(OBJECTS) *~ *.swp dislocker $(BIN)

valgrind: clean $(BIN)
	valgrind --leak-check=full --show-reachable=yes ./$(BIN) $(ARGS)

snapshot: clean
	cd .. && (git status | grep -q 'nothing to commit' || git commit -a -m 'Snapshot v$(VERSION)') && git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD | gzip > /tmp/$(BIN)-$(DATE).tar.gz

release: clean
	cd .. && (git status | grep -q 'nothing to commit' || git commit -a) && git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD | gzip > /tmp/$(BIN)-$(VERSION).tar.gz

