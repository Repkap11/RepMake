BEFORE_VARS := $(.VARIABLES)

TARGET=repmake

CPUS ?= $(shell nproc || echo 1)
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --jobs=$(CPUS)
MAKEFLAGS += --no-print-directory

# Remove built in rules
MAKEFLAGS += --no-builtin-rules

# Use -Wno-attributes due to an antlr bug https://github.com/antlr/antlr4/issues/3217
CFLAGS_ANTLR = -std=c++11 -Wno-attributes
CFLAGS_CPP = -Wall -Wextra -std=c++11 -Wno-unused-parameter -Wno-unused-variable -Wno-attributes

# CFLAGS += -O3
CFLAGS_ANTLR += -g
CFLAGS_CPP += -g


OBJECTS = \
	$(patsubst src/cpp/%.cpp,out/%.o, $(wildcard src/cpp/*.cpp)) \
	$(patsubst out/antlr_src/%.cpp,out/antlr_out/%.o, $(wildcard out/antlr_src/*.cpp)) \
	out/antlr_runtime/runtime/libantlr4_cpp_runtime.a

INCLUDES_ANTLR = -I libs/antlr4-cpp-runtime/runtime/src/
INCLUDES_CPP = $(INCLUDES_ANTLR) -I include/  -I out/antlr_src

DEPS = \
	$(patsubst src/cpp/%.cpp,out/%.d, $(wildcard src/cpp/*.cpp)) \
	$(patsubst out/antlr_src/%.cpp,out/antlr_out/%.d, $(wildcard out/antlr_src/*.cpp))

all: out/$(TARGET)

dev: out/$(TARGET)
	@cd example && ../$< RepMake

out:
	mkdir -p $@
	
clean:
	rm -rf out

.PHONY: all dev clean

out/%.o: src/cpp/%.cpp out/antlr_src | out
	@#Use g++ to build o file and a dependecy tree .d file for every cpp file
	ccache g++ $(INCLUDES_CPP) $(CFLAGS_CPP) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $(patsubst %.d,%.o,$@) -c $< -o $@

out/antlr_src/%.cpp: src/antlr/RepMake.g4 out/antlr_src
	touch $@

out/antlr_out:
	mkdir -p $@

out/antlr_out/%.o: out/antlr_src/%.cpp src/antlr/RepMake.g4 | out/antlr_out
	ccache g++ $(INCLUDES_ANTLR) $(CFLAGS_ANTLR) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $(patsubst %.d,%.o,$@) -c $< -o $@

out/antlr_src: src/antlr/RepMake.g4
	rm -rf $@
	antlr4 -no-listener -message-format gnu -Xexact-output-dir -Dlanguage=Cpp $< -o $@

out/antlr_runtime/Makefile:
	mkdir -p out/antlr_runtime
	cd out/antlr_runtime && cmake ../../libs/antlr4-cpp-runtime/
	
out/antlr_runtime/runtime/libantlr4_cpp_runtime.a: out/antlr_runtime/Makefile
	$(MAKE) -C out/antlr_runtime

-include $(DEPS)

out/$(TARGET): $(OBJECTS)
	g++ -flto $(CFLAGS_CPP) $(OBJECTS) -o $@


.PRECIOUS: out/$(TARGET) $(OBJECTS)

vars:
	@echo "$(BEFORE_VARS) $(AFTER_VARS)" | xargs -n1 | sort | uniq -u

AFTER_VARS := $(.VARIABLES)

nothing:

# $(info Val: [$(DEPS)])