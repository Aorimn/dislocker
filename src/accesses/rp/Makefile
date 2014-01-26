PROGNAME	=	recovery_password
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
INC		=	-I/usr/include -I../../
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC)
LDFLAGS		=	$(LIB) -lpolarssl
SOURCES		=	*.c ../stretch_key.c
OBJECTS		=	$(patsubst %.c, %.o, $(wildcard *.c)) ../stretch_key.o ../../xstd/xstdio.o ../../xstd/xstdlib.o
BIN		=	$(PROGNAME)


# For MacOSX users
ifeq ($(OS), Darwin)
DEFINES		+=	-D__DARWIN
else
# Useless warnings when used within Darwin
WFLAGS		+=	-Wconversion
endif


ifdef DEBUG
DBGFLAGS	=	-ggdb -D DEBUG=$(DEBUGs)
CFLAGS		+=	$(DBGFLAGS)
endif


.PHONY : all library $(BIN) clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	@$(MAKE) DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $^ ../../common.o $(LDFLAGS)

library : recovery_password.o

clean :
	rm -rf -- *.o $(BIN) *~ *.swp
	@$(MAKE) -C ../../ clean

