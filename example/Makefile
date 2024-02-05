OLD_SHELL := $(SHELL)
SHELL = ../out/RepShell \
		--ignore libgcc_s.so.1 \
		--shell $(OLD_SHELL) \
		--task $@  --

MAKEFLAGS += -k # Continue after failed targets as much as possible.

all:
	./example

-include .RepDep

build: example

example:
	gcc example.o lib.o -o example

example.o:
	gcc -c example.c -o example.o

lib.o:
	gcc -c lib.c -o lib.o -I inc1 -I inc2

clean:
	rm -f *.o example
