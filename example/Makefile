OLD_SHELL := $(SHELL)
SHELL = ../out/RepShell \
		--ignore libgcc_s.so.1 \
		--shell $(OLD_SHELL) \
		--task $@  --
MAKEFLAGS += --jobs=12
MAKEFLAGS += -k # Continue after failed targets as much as possible.

all:
	./example

-include RepDep.d

build: example

example:
	ccache gcc example.o lib.o -o example

example.o:
	ccache gcc -c example.c -o example.o

lib.o:
	ccache gcc -c lib.c -o lib.o -I inc1 -I inc2

clean:
	rm -f *.o example
