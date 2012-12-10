
.PHONY : library clean

library:
	@make DEBUG=$(DEBUG) -C bek/ library
	@make DEBUG=$(DEBUG) -C rp/ library

clean:
	@make -C bek/ clean
	@make -C rp/ clean
