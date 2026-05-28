JSONCPP_SRC := /targets/jsoncpp

# Separate cmake build dir per compiler so AFL and coverage builds don't collide.
_CXX_SLUG   := $(shell printf '%s' '$(CXX)' | tr '+/ @' '____')
BUILD_DIR   := $(JSONCPP_SRC)/cmake_build_$(_CXX_SLUG)

.PHONY: all clean jsoncpp_fuzzer ir clean-ir

.PHONY: ast_dump

all: jsoncpp_fuzzer

ast_dump:
	clang -Xclang -ast-dump -fsyntax-only \
	    -I$(JSONCPP_SRC)/include \
	    -I$(JSONCPP_SRC)/src/test_lib_json \
	    $(JSONCPP_SRC)/src/test_lib_json/fuzz.cpp

IR_DIR ?= $(CURDIR)/ir
IR_CXX ?= $(CXX)
IR_SOURCES := \
    $(JSONCPP_SRC)/src/lib_json/json_reader.cpp \
    $(JSONCPP_SRC)/src/lib_json/json_value.cpp \
    $(JSONCPP_SRC)/src/lib_json/json_writer.cpp \
    $(JSONCPP_SRC)/src/test_lib_json/fuzz.cpp \
    $(CURDIR)/main_stub.cpp

ir:
	mkdir -p $(IR_DIR)
	@set -e; \
	for src in $(IR_SOURCES); do \
	    base=$$(basename "$$src"); \
	    out="$(IR_DIR)/$${base%.*}.ll"; \
	    echo "[ir] $$src -> $$out"; \
	    $(IR_CXX) $(CXXFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(JSONCPP_SRC)/include \
	        -I$(JSONCPP_SRC)/src/lib_json \
	        -I$(JSONCPP_SRC)/src/test_lib_json \
	        -o "$$out" "$$src"; \
	done

# Always recompile so each invocation uses the current CXX/CXXFLAGS.
# main_stub.cpp provides a plain file-reading main() — avoids the
# persistent-mode / shmem conflict that occurs when libAFLDriver.a is linked
# alongside afl-clang-fast++-instrumented code.
jsoncpp_fuzzer: $(BUILD_DIR)/lib/libjsoncpp.a
	$(CXX) $(CXXFLAGS) \
	    -I$(JSONCPP_SRC)/include \
	    -I$(JSONCPP_SRC)/src/test_lib_json \
	    $(JSONCPP_SRC)/src/test_lib_json/fuzz.cpp \
	    $(CURDIR)/main_stub.cpp \
	    -o $(CURDIR)/jsoncpp_fuzzer \
	    $(BUILD_DIR)/lib/libjsoncpp.a

# Build jsoncpp static library with the same compiler (cached per compiler slug).
# CFLAGS/CXXFLAGS are cleared for cmake so instrumentation flags (e.g.
# -fprofile-instr-generate) don't leak into cmake's try_compile feature tests,
# which would fail to link without the profiling runtime.
$(BUILD_DIR)/lib/libjsoncpp.a:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && CFLAGS= CXXFLAGS= cmake \
	    -DCMAKE_C_COMPILER="$(CC)" \
	    -DCMAKE_CXX_COMPILER="$(CXX)" \
	    -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF \
	    -DJSONCPP_WITH_TESTS=OFF \
	    -DBUILD_SHARED_LIBS=OFF \
	    -G "Unix Makefiles" \
	    $(JSONCPP_SRC)
	CFLAGS= CXXFLAGS= $(MAKE) -C $(BUILD_DIR) -j$(shell nproc 2>/dev/null || echo 1)

clean:
	rm -rf $(JSONCPP_SRC)/cmake_build_* jsoncpp_fuzzer

clean-ir:
	rm -rf $(IR_DIR)
