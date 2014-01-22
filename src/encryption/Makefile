PROGNAME	=	encryption

INC		=	-I/usr/include -I..
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) 
LDFLAGS		=	$(LIB) # -lcrypto
SOURCES		=	*.c
OBJECTS		=	$(patsubst %.c, %.o, $(wildcard *.c))
BIN		=	$(PROGNAME)

EXT_OBJ		=	../common.o \
			../ntfs/guid.o ../ntfs/clock.o ../ntfs/encoding.o \
			../metadata/datums.o ../metadata/vmk.o ../metadata/metadata.o \
			../xstd/xstdio.o ../xstd/xstdlib.o \
			../accesses/rp/recovery_password.o ../accesses/bek/read_bekfile.o \
			../polarssl/aes.o ../polarssl/sha2.o


ifeq ($(ARCH), x86_64)
LIB		= 	-L/usr/lib64
else
LIB		= 	-L/usr/lib
endif

# For MacOSX users
ifneq ($(OS), Darwin)
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
	@$(MAKE) -C ../polarssl/ library
	@$(MAKE) DEBUG=$(DEBUG) -C ../ common
	@$(MAKE) DEBUG=$(DEBUG) -C ../metadata/ library
	@$(MAKE) DEBUG=$(DEBUG) -C ../accesses/ library
	$(CC) $(CFLAGS) -o $@ $(EXT_OBJ) $^ $(LDFLAGS)

library : decrypt.o encrypt.o diffuser.o crc32.o
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean :
	@$(MAKE) -C ../polarssl/ clean
	@$(MAKE) -C ../ clean
	@$(MAKE) -C ../metadata/ clean
	rm -rf -- *.o $(BIN) $(EXT_OBJ) *~ *.swp

