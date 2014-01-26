PROGNAME	=	getmetadata
AUTHOR		=	\"Romain Coltel\"
ARCH		=	$(shell uname -m)
OS		=	$(shell uname -s)
# DEBUG		=	1

ifeq ($(OS), FreeBSD)
MAKE		=	gmake
else
MAKE		=	make
endif

CC		=	cc
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\" -D_FILE_OFFSET_BITS=64
INC		=	-I/usr/include -I..
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC)
LDFLAGS		=	$(LIB) -lpolarssl
SOURCES		=	main.c metadata.c datums.c vmk.c extended_info.c
OBJECTS		=	$(SOURCES:.c=.o)
BIN		=	$(PROGNAME)

EXT_OBJ		=	../common.o ../encryption/crc32.o ../encryption/decrypt.o ../encryption/diffuser.o \
			../accesses/rp/recovery_password.o ../accesses/bek/read_bekfile.o \
			../accesses/user_pass/user_pass.o ../accesses/stretch_key.o \
			../ntfs/guid.o ../ntfs/clock.o ../ntfs/encoding.o \
			../xstd/xstdio.o ../xstd/xstdlib.o


ifeq ($(ARCH), x86_64)
CFLAGS		+= 	-D __ARCH_X86_64
endif

# For MacOSX users
ifeq ($(OS), Darwin)
DEFINES		+=	-D__DARWIN
else
# Useless warnings when used within Darwin
WFLAGS		+=	-Wconversion
endif


ifdef DEBUG
DBGFLAGS	=	-ggdb -D DEBUG=$(DEBUG)
CFLAGS		+=	$(DBGFLAGS)
endif



.PHONY : all $(BIN) library clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	@$(MAKE) DEBUG=$(DEBUG) -C .. common
	@$(MAKE) DEBUG=$(DEBUG) -C ../encryption library
	@$(MAKE) DEBUG=$(DEBUG) -C ../accesses library
	$(CC) $(CFLAGS) -o $@ $^ $(EXT_OBJ) $(LDFLAGS)

library: metadata.o vmk.o fvek.o datums.o extended_info.o

clean :
	@$(MAKE) -C ../ clean
	rm -rf -- *.o $(BIN) *~ *.swp

