SHELL = ../out/repshell $@

all: example
	./example

build: example

example: lib.o example.o
	gcc example.o lib.o -o example

example.o:
	gcc -c example.c -o example.o

lib.o:
	gcc -c lib.c -o lib.o
