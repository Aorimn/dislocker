PROGNAME	=	getmetadata
AUTHOR		=	\"Romain Coltel\"
ARCH		=	$(shell uname)
# DEBUG		=	1

CC		=	gcc
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\" -D_FILE_OFFSET_BITS=64
INC		=	-I/usr/include -I..
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(LIB)
# LDFLAGS		=	-lcrypto
SOURCES		=	main.c metadata.c datums.c vmk.c extended_info.c
OBJECTS		=	$(SOURCES:.c=.o)
BIN		=	$(PROGNAME)

EXT_OBJ		=	../common.o ../encryption/crc32.o ../encryption/decrypt.o ../encryption/diffuser.o \
			../accesses/rp/recovery_password.o ../accesses/bek/read_bekfile.o \
			../accesses/user_pass/user_pass.o ../accesses/stretch_key.o \
			../ntfs/guid.o ../ntfs/clock.o ../ntfs/encoding.o \
			../xstd/xstdio.o ../xstd/xstdlib.o \
			../polarssl/aes.o ../polarssl/sha2.o


ifeq ($(shell uname -m), x86_64)
LIB		= 	-L/usr/lib64
CFLAGS		+= 	-D __ARCH_X86_64
else
LIB		= 	-L/usr/lib
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



.PHONY : all $(BIN) library clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	@make -C ../polarssl/ library
	@make DEBUG=$(DEBUG) -C .. common
	@make DEBUG=$(DEBUG) -C ../encryption library
	@make DEBUG=$(DEBUG) -C ../accesses library
	$(CC) $(CFLAGS) -o $@ $^ $(EXT_OBJ) $(LDFLAGS)

library: metadata.o vmk.o fvek.o datums.o extended_info.o
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean :
	@make -C ../polarssl/ clean
	@make -C ../ clean
	rm -rf -- *.o $(BIN) *~ *.swp

