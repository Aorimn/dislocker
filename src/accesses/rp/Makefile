PROGNAME	=	recovery_password

INC		+=	-I../../
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC)
LDFLAGS		=	$(LIB) # -lcrypto
SOURCES		=	*.c ../stretch_key.c
OBJECTS		=	$(patsubst %.c, %.o, $(wildcard *.c)) ../stretch_key.o ../../xstd/xstdio.o ../../xstd/xstdlib.o
BIN		=	$(PROGNAME)

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
DBGFLAGS	=	-ggdb -D DEBUG=$(DEBUGs)
CFLAGS		+=	$(DBGFLAGS)
endif


.PHONY : all library $(BIN) clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	@$(MAKE) -C ../../polarssl library
	@$(MAKE) DEBUG=$(DEBUG) -C ../../ common
	$(CC) $(CFLAGS) -o $@ $^ ../../common.o ../../polarssl/sha2.o $(LDFLAGS)

library : recovery_password.o
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean :
	rm -rf -- *.o $(BIN) *~ *.swp
	@$(MAKE) -C ../../ clean
	@$(MAKE) -C ../../polarssl clean

