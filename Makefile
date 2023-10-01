BEFORE_VARS := $(.VARIABLES)

TARGET=repmake

CPUS ?= $(shell nproc || echo 1)
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --jobs=$(CPUS)
MAKEFLAGS += --no-print-directory

CFLAGS := -Wall -Wextra -std=c++11 -Wno-unused-parameter -Wno-unused-variable

OBJECTS := $(patsubst src/cpp/%.cpp,out/%.o, $(wildcard src/cpp/*.cpp))
INCLUDES := -I include/
# CFLAGS += -O3
CFLAGS += -g
DEPS := $(patsubst src/cpp/%.cpp,out/%.d, $(wildcard src/cpp/*.cpp))

all: out/$(TARGET)

dev: out/$(TARGET)
	./$<

out:
	mkdir -p $@
	
clean:
	rm -rf out

out/%.o: src/cpp/%.cpp | out
	@#Use g++ to build o file and a dependecy tree .d file for every cpp file
	ccache g++ $(INCLUDES) $(CFLAGS) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $(patsubst %.d,%.o,$@) -c $< -o $@

out/antlr: src/antlr/repmake.g4
	antlr4 -Xexact-output-dir -Dlanguage=Cpp $< -o $@

out/antlr_runtime/Makefile:
	mkdir -p out/antlr_runtime
	cd out/antlr_runtime && cmake ../../libs/antlr4-cpp-runtime/
	
out/antlr_runtime/runtime/libantlr4_cpp_runtime.a: out/antlr_runtime/Makefile
	$(MAKE) -C out/antlr_runtime

-include $(DEPS)

out/$(TARGET):  $(OBJECTS)
	g++ -flto $(CFLAGS) $(OBJECTS) -o $@


.PRECIOUS: out/$(TARGET) $(OBJECTS)

vars:
	@echo "$(BEFORE_VARS) $(AFTER_VARS)" | xargs -n1 | sort | uniq -u

AFTER_VARS := $(.VARIABLES)
ALL_VARS := $(shell echo "$(BEFORE_VARS) $(AFTER_VARS)" | xargs -n1 | sort | uniq -u | grep -v "^GUARD$$" | grep -v "^TEST_RULE$$" | grep -v "^CHECK$$" | grep -v "^BEFORE_VARS$$")
ALL_VAR_DEPS = $(call GUARD,${ALL_VARS})
.PRECIOUS: ${ALL_VAR_DEPS}

# $(info Val: [${DEPS}])