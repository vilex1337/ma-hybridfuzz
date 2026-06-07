LIBPNG_SRC  := /targets/libpng
FUZZER_SRC  := $(LIBPNG_SRC)/contrib/oss-fuzz/libpng_read_fuzzer.cc

_CXX_SLUG   := $(shell printf '%s' '$(CXX)' | tr '+/ @' '____')
BUILD_DIR   := $(LIBPNG_SRC)/build_$(_CXX_SLUG)

IR_DIR     ?= $(CURDIR)/ir
IR_CXX     ?= $(CXX)
IR_CC      ?= $(CC)
IR_SOURCES  := $(FUZZER_SRC) $(CURDIR)/main_stub.cpp
LIBPNG_C_SRCS := $(wildcard $(LIBPNG_SRC)/*.c)

.PHONY: all clean ir

all: libpng_read_fuzzer

ir: $(BUILD_DIR)/libpng16.a
	mkdir -p $(IR_DIR)
	@for src in $(LIBPNG_C_SRCS); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/lib_$${base%.*}.ll"; \
	    $(IR_CC) $(CFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(LIBPNG_SRC) -I$(BUILD_DIR) \
	        -o "$$out" "$$src" 2>/dev/null || true; done
	@set -e; for src in $(IR_SOURCES); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/$${base%.*}.ll"; \
	    echo "[ir] $$src -> $$out"; \
	    $(IR_CXX) $(CXXFLAGS) -S -emit-llvm -g -O0 -w -include cstdlib \
	        -I$(LIBPNG_SRC) -I$(BUILD_DIR) \
	        -o "$$out" "$$src"; done

libpng_read_fuzzer: $(BUILD_DIR)/libpng16.a
	$(CXX) $(CXXFLAGS) -std=c++11 -include cstdlib \
	    -I$(LIBPNG_SRC) -I$(BUILD_DIR) \
	    $(FUZZER_SRC) $(CURDIR)/main_stub.cpp \
	    -o $(CURDIR)/libpng_read_fuzzer \
	    $(BUILD_DIR)/libpng16.a -lz

$(BUILD_DIR)/libpng16.a:
	cd $(LIBPNG_SRC) && autoreconf -f -i
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && CFLAGS= CXXFLAGS= $(LIBPNG_SRC)/configure \
	    CC="$(CC)" CXX="$(CXX)" --disable-shared
	CFLAGS= CXXFLAGS= $(MAKE) -C $(BUILD_DIR) -j$$(nproc 2>/dev/null || echo 1) libpng16.la
	cp $(BUILD_DIR)/.libs/libpng16.a $(BUILD_DIR)/libpng16.a

clean:
	rm -rf $(BUILD_DIR) $(CURDIR)/libpng_read_fuzzer

clean-ir:
	rm -rf $(IR_DIR)
