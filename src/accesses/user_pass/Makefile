PROGNAME	=	user_pass
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
MAIN_OBJECT	=	
SOURCES		=	user_pass.c ../stretch_key.c
OBJECTS		=	$(SOURCES:.c=.o) ../stretch_key.o \
			../../xstd/xstdio.o ../../xstd/xstdlib.o \
			../../ntfs/encoding.o
BIN		=	$(PROGNAME)


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


.PHONY : all library $(BIN) clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : MAIN_OBJECT = main.o
all : main.o
all : $(BIN)

check : MAIN_OBJECT = check_user_pass.o
check : check_user_pass.o
check : DEFINES += -D__CK_DOING_TESTS
check : CFLAGS  += -fprofile-arcs -ftest-coverage
check : LDFLAGS += -lcheck
check : do_check

do_check : $(BIN)
	./$(BIN)
	gcov $(BIN).c

$(BIN) : $(OBJECTS)
	@$(MAKE) DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $(MAIN_OBJECT) $^ ../../common.o $(LDFLAGS)

library : user_pass.o

clean :
	rm -rf -- $(BIN) *.o *~ *.swp *.gcno *.gcda *.gcov
	@$(MAKE) -C ../../ clean

