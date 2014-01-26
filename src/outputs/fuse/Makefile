PROGNAME	=	fuse
AUTHOR		=	\"Romain Coltel\"
ARCH		=	$(shell uname -m)
OS		=	$(shell uname -s)
# DEBUG		=	1

ifeq ($(OS), FreeBSD)
MAKE		=	gmake
else
MAKE		=	make
endif

USE_FUSE	=	1

CC		=	gcc
DEFINES		=	-D PROGNAME=\"$(PROGNAME)\" -D_FILE_OFFSET_BITS=64
DEFINES		+=	-DAUTHOR="$(AUTHOR)" -D__OS=\"$(OS)\" -D__ARCH=\"$(ARCH)\"
DEFINES		+=	-D__ARCH_$(shell echo $(ARCH) | tr a-z A-Z) -D__$(shell echo $(OS) | tr a-z A-Z)
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES)
LDFLAGS		=	$(LIB)
SOURCES		=	main.c
OBJECTS		=	$(SOURCES:.c=.o) ../../xstd/xstdio.o ../../xstd/xstdlib.o
BIN		=	$(PROGNAME)

EXT_OBJ		=	../../common.o



# For MacOSX users
ifeq ($(OS), Darwin)
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

clean :
	@make -C ../../ clean
	rm -rf -- *.o $(BIN) *~ *.swp

