
CC		=	gcc
INC		=	-I/usr/include -I../
CFLAGS		=	$(INC)

SOURCES		=	aes.c sha2.c
OBJECTS		=	$(SOURCES:.c=.o)


.PHONY : all library clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<


all : $(OBJECTS)

library : all
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean :
	rm -rf -- *.o *~ *.swp
