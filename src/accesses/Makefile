INC		+=	-I..
CFLAGS		=	$(WFLAGS) $(DEFINES) $(INC)


.PHONY : library clean

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

library: stretch_key.o
	@$(MAKE) DEBUG=$(DEBUG) -C bek/ library
	@$(MAKE) DEBUG=$(DEBUG) -C rp/ library
	@$(MAKE) DEBUG=$(DEBUG) -C user_pass/ library

clean:
	@$(MAKE) -C bek/ clean
	@$(MAKE) -C rp/ clean
	@$(MAKE) -C user_pass/ clean
	rm -rf -- stretch_key.o
