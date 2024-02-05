SHELL = ../out/RepShell --task $@ --
p
all:
	./example

-include .RepDep

build: example

example:
	gcc example.o lib.o -o example

example.o:
	gcc -c example.c -o example.o

lib.o:
	gcc -c lib.c -o lib.o

clean:
	rm -f *.o example
