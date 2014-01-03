PROGNAME	=	user_pass
AUTHOR		=	\"Romain Coltel\"
ARCH		=	$(shell uname)
# DEBUG		=	1

CC		=	gcc
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\" -D_FILE_OFFSET_BITS=64
INC		=	-I/usr/include -I../../
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC) $(LIB)
# LDFLAGS		=	-lcrypto
LDFLAGS		=	-lpolarssl
SOURCES		=	*.c ../stretch_key.c
OBJECTS		=	$(patsubst %.c, %.o, $(wildcard *.c)) ../stretch_key.o ../../xstd/xstdio.o ../../xstd/xstdlib.o
BIN		=	$(PROGNAME)


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
	@make DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $^ ../../common.o $(LDFLAGS)

library : user_pass.o
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean :
	rm -rf -- *.o $(BIN) *~ *.swp
	@make -C ../../ clean

