PROGNAME	=	read_bekfile
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
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\"
INC		=	-I/usr/include -I../..
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC)
SOURCES		=	*.c
OBJECTS		=	$(patsubst %.c, %.o, $(wildcard *.c))
LDFLAGS		=	$(LIB)
BIN		=	$(PROGNAME)

EXT_OBJ		=	../../common.o ../../metadata/datums.o ../../metadata/extended_info.o \
			../../ntfs/guid.o ../../ntfs/clock.o ../../ntfs/encoding.o \
			../../xstd/xstdio.o ../../xstd/xstdlib.o



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
	@$(MAKE) DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $^ $(EXT_OBJ)

library : read_bekfile.o

clean :
	@$(MAKE) -C ../../ clean
	rm -rf -- *.o $(BIN) *~ *.swp


