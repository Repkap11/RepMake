BEFORE_VARS := $(.VARIABLES)

TARGET=repshell

CPUS ?= $(shell nproc || echo 1)
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --jobs=$(CPUS)
MAKEFLAGS += --no-print-directory

# Remove built in rules
MAKEFLAGS += --no-builtin-rules

CFLAGS_CPP = -Wall -Werror -Wextra -std=c++11 -Wno-unused-parameter -Wno-unused-variable -Wno-attributes -Wno-unused-function

# CFLAGS_CPP += -O3
CFLAGS_CPP += -g
# 

OBJECTS = $(patsubst src/%.cpp,out/%.o, $(wildcard src/*.cpp)) 

INCLUDES_CPP = -I include/

DEPS = $(patsubst src/%.cpp,out/%.d, $(wildcard src/*.cpp)) 

all: out/$(TARGET)

dev: out/$(TARGET)
	cd example && make

valgrind: out/$(TARGET)
	@cd example && valgrind --leak-check=full -s ../$< -c "touch Test"

out:
	mkdir -p $@
	
clean:
	rm -rf out

.PHONY: all dev clean valgrind

out/%.o: src/%.cpp  Makefile | out
	@#Use g++ to build o file and a dependecy tree .d file for every cpp file
	ccache g++ $(INCLUDES_CPP) $(CFLAGS_CPP) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $(patsubst %.d,%.o,$@) -c $< -o $@

-include $(DEPS)

out/$(TARGET): $(OBJECTS)
	g++ -flto $(CFLAGS_CPP) $(OBJECTS) -o $@


.PRECIOUS: out/$(TARGET) $(OBJECTS)

clean-example:
	rm -f example/example
	rm -f example/*.o
# sleep 1
# touch example/*.c

vars:
	@echo "$(BEFORE_VARS) $(AFTER_VARS)" | xargs -n1 | sort | uniq -u

AFTER_VARS := $(.VARIABLES)

nothing:

# $(info Val: [$(DEPS)])