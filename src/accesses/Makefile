PROGNAME	=	dislocker
AUTHOR		=	\"Romain Coltel\"
VERSION		=	0.2.3
ARCH		=	$(shell uname)
DATE		=	$(shell date +%Y-%m-%d)

CC		=	gcc
DEFINES		=	-DPROGNAME=\"$(PROGNAME)\" -DVERSION=\"$(VERSION)\" -D_FILE_OFFSET_BITS=64
INC		=	-I/usr/include -I..
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC)


.PHONY : library clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

library: stretch_key.o
	@make DEBUG=$(DEBUG) -C bek/ library
	@make DEBUG=$(DEBUG) -C rp/ library
	@make DEBUG=$(DEBUG) -C user_pass/ library

clean:
	@make -C bek/ clean
	@make -C rp/ clean
	@make -C user_pass/ clean
	rm -rf -- stretch_key.o
