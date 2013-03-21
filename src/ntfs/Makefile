
CC		=	gcc
INC		=	-I/usr/include -I../
WFLAGS		=	-Wall -Werror -Wextra
CFLAGS		=	$(WFLAGS) $(INC)

SOURCES		=	guid.c clock.c encoding.c
OBJECTS		=	$(SOURCES:.c=.o)


.PHONY : all library clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<


all: $(OBJECTS)

library: all
	@echo -n "" # He wants a rule here... Do not ask me why :D

clean:
	rm $(OBJECTS)
