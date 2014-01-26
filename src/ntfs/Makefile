INC		+=	-I../
CFLAGS		=	$(WFLAGS) $(INC)

SOURCES		=	guid.c clock.c encoding.c
OBJECTS		=	$(SOURCES:.c=.o)


.PHONY : all library clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<


all: $(OBJECTS)

library: all

clean:
	rm $(OBJECTS)
