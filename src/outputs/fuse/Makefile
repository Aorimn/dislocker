PROGNAME	=	fuse
AUTHOR		=	\"Romain Coltel\"
ARCH		=	$(shell uname)
# DEBUG		=	1

USE_FUSE	=	1

CC		=	gcc
DEFINES		=	-D PROGNAME=\"$(PROGNAME)\" -D __XYSSL
INC		=	-I/usr/include -I../..
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(LIB)
# LDFLAGS		=	-lcrypto
SOURCES		=	main.c
OBJECTS		=	$(SOURCES:.c=.o) ../../xstd/xstdio.o ../../xstd/xstdlib.o
BIN		=	$(PROGNAME)

EXT_OBJ		=	../../common.o


ifeq ($(shell uname -m), x86_64)
LIB		= 	-L/usr/lib64
else
LIB		= 	-L/usr/lib
endif

# For MacOSX users
ifeq ($(shell uname -s), Darwin)
DEFINES		+=	-D__DARWIN
LDFLAGS		+=	-losxfuse_i64
else
LDFLAGS		+=	-lfuse
# Useless warnings when used within Darwin
WFLAGS		+=	-Wconversion
endif


ifdef DEBUG
DBGFLAGS	=	-ggdb -D DEBUG=$(DEBUG)
CFLAGS		+=	$(DBGFLAGS)
endif

ifeq ($(USE_FUSE), 1)
DEFINES		+=	-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26
endif


.PHONY : all $(BIN) library clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	@make DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $^ $(EXT_OBJ) $(LDFLAGS)

library : fuse.o
	@echo -n ""  # He wants a rule here... Do not ask me why :D

clean :
	@make -C ../../ clean
	rm -rf -- *.o $(BIN) *~ *.swp

