.PHONY: all
all: nyufile

nyufile: nyufile.o
	gcc -o nyufile nyufile.o -lm -lcrypto

nyufile.o: nyufile.c 
	gcc -c nyufile.c -lm -lcrypto

.PHONY: clean
clean:
	rm -f *.o nyufile
