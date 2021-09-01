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
CHARDEN		=	-fstack-protector -fPIC -D_FORTIFY_SOURCE=2 -O1
LHARDEN		=	-pie -fPIE -Wl,-z,relro -Wl,-z,now
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(CHARDEN)
SOURCES		=	main.c read_bekfile.c
OBJECTS		=	$(SOURCES:.c=.o)
override LDFLAGS    +=	$(LIB) $(LHARDEN)
BIN		=	$(PROGNAME)

EXT_OBJ		=	../../common.o ../../metadata/datums.o ../../metadata/print_metadata.o \
			../../metadata/extended_info.o ../../metadata/vmk.o \
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


export

.PHONY : all $(BIN) library clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	@$(MAKE) DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $^ $(EXT_OBJ) $(LDFLAGS)

library : read_bekfile.o

clean :
	@$(MAKE) -C ../../ clean
	rm -rf -- $(BIN) *.o *~ *.swp *.gcno *.gcda *.gcov
