.PHONY: all
all: nyufile

nyufile: nyufile.o
	gcc -o nyufile nyufile.o -lm

nyufile.o: nyufile.c 
	gcc -c nyufile.c -lm

.PHONY: clean
clean:
	rm -f *.o nyufile
