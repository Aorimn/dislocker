PROGNAME	=	read_bekfile
AUTHOR		=	\"Romain Coltel\"
ARCH		=	$(shell uname)
# DEBUG		=	1

CC		=	gcc
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\"
INC		=	-I/usr/include -I../..
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(LIB)
SOURCES		=	*.c
OBJECTS		=	$(patsubst %.c, %.o, $(wildcard *.c))
BIN		=	$(PROGNAME)

EXT_OBJ		=	../../common.o ../../metadata/datums.o \
			../../ntfs/guid.o ../../ntfs/clock.o ../../ntfs/encoding.o \
			../../xstd/xstdio.o ../../xstd/xstdlib.o



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
	@make DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $^ $(EXT_OBJ)

library : read_bekfile.o
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean :
	@make -C ../../ clean
	rm -rf -- *.o $(BIN) *~ *.swp


