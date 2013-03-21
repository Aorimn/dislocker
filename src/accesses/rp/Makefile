PROGNAME	=	recovery_password
AUTHOR		=	\"Romain Coltel\"
ARCH		=	$(shell uname)
# DEBUG		=	1

CC		=	gcc
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\" -D_FILE_OFFSET_BITS=64
INC		=	-I/usr/include -I../../
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(LIB)
# LDFLAGS		=	-lcrypto
SOURCES		=	*.c ../stretch_key.c
OBJECTS		=	$(patsubst %.c, %.o, $(wildcard *.c)) ../stretch_key.o ../../xstd/xstdio.o ../../xstd/xstdlib.o
BIN		=	$(PROGNAME)

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
DBGFLAGS	=	-ggdb -D DEBUG=$(DEBUGs)
CFLAGS		+=	$(DBGFLAGS)
endif


.PHONY : all library $(BIN) clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	@make -C ../../polarssl library
	@make DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $^ ../../common.o ../../polarssl/sha2.o $(LDFLAGS)

library : recovery_password.o
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean :
	rm -rf -- *.o $(BIN) *~ *.swp
	@make -C ../../ clean
	@make -C ../../polarssl clean

