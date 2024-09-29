OLD_SHELL := $(SHELL)
SHELL = ../out/RepShell \
		--ignore libgcc_s.so.1 \
		--shell $(OLD_SHELL) \
		--task $@ -- 

# Continue after failed targets as much as possible.
# This allows the build to make progress 1 depth layer at a time,
# instead of 1 at a time.
MAKEFLAGS += -k 

## Normal makefile without dependencies below
MAKEFLAGS += --jobs=12

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
