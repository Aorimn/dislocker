PROGNAME	=	read_bekfile

INC		+=	-I../..
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC)
SOURCES		=	*.c
OBJECTS		=	$(patsubst %.c, %.o, $(wildcard *.c))
LDFLAGS		=	$(LIB)
BIN		=	$(PROGNAME)

EXT_OBJ		=	../../common.o ../../metadata/datums.o \
			../../ntfs/guid.o ../../ntfs/clock.o ../../ntfs/encoding.o \
			../../xstd/xstdio.o ../../xstd/xstdlib.o


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
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	@$(MAKE) DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $^ $(EXT_OBJ) $(LDFLAGS)

library : read_bekfile.o
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean :
	@$(MAKE) -C ../../ clean
	rm -rf -- *.o $(BIN) *~ *.swp


