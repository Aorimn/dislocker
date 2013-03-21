PROGNAME	=	encryption
AUTHOR		=	\"Romain Coltel\"
ARCH		=	$(shell uname)
# DEBUG		=	1


CC		=	gcc
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\" -D_FILE_OFFSET_BITS=64
INC		=	-I/usr/include -I..
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(LIB)
# LDFLAGS		=	-lcrypto
SOURCES		=	*.c
OBJECTS		=	$(patsubst %.c, %.o, $(wildcard *.c))
BIN		=	$(PROGNAME)

EXT_OBJ		=	../common.o \
			../ntfs/guid.o ../ntfs/clock.o ../ntfs/encoding.o \
			../metadata/datums.o ../metadata/vmk.o ../metadata/metadata.o \
			../xstd/xstdio.o ../xstd/xstdlib.o \
			../accesses/rp/recovery_password.o ../accesses/bek/read_bekfile.o \
			../polarssl/aes.o ../polarssl/sha2.o


ifeq ($(shell uname -m), x86_64)
LIB		= 	-L/usr/lib64
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
	$(CC) $(CFLAGS) $(LIBRARY_FLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	@make -C ../polarssl/ library
	@make DEBUG=$(DEBUG) -C ../ common
	@make DEBUG=$(DEBUG) -C ../metadata/ library
	@make DEBUG=$(DEBUG) -C ../accesses/ library
	$(CC) $(CFLAGS) -o $@ $(EXT_OBJ) $^ $(LDFLAGS)

library : decrypt.o encrypt.o diffuser.o crc32.o
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean :
	@make -C ../polarssl/ clean
	@make -C ../ clean
	@make -C ../metadata/ clean
	rm -rf -- *.o $(BIN) $(EXT_OBJ) *~ *.swp

