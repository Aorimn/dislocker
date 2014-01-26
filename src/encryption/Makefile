INC		+=	-I..
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC)


.PHONY : library clean

.c.o :
	$(CC) $(CFLAGS) $(LIBRARY_FLAGS) -c -o $@ $<

library : decrypt.o encrypt.o diffuser.o crc32.o

clean :
	@$(MAKE) -C ../ clean
	@$(MAKE) -C ../metadata/ clean
	rm -rf -- *.o $(BIN) $(EXT_OBJ) *~ *.swp

