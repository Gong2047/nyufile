.PHONY: all
all: nyufile

nyufile: nyufile.o
	gcc -pthread -o nyufile nyufile.o

nyufile.o: nyufile.c 
	gcc -pthread -c nyufile.c

.PHONY: clean
clean:
	rm -f *.o nyufile
