LIBTIFF_SRC := /targets/libtiff
FUZZER_SRC  := $(LIBTIFF_SRC)/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc

_CXX_SLUG   := $(shell printf '%s' '$(CXX)' | tr '+/ @' '____')
INSTALL_DIR := $(LIBTIFF_SRC)/install_$(_CXX_SLUG)
BUILD_DIR   := $(INSTALL_DIR)/build

IR_DIR     ?= $(CURDIR)/ir
IR_CXX     ?= $(CXX)
IR_CC      ?= $(CC)
IR_SOURCES  := $(FUZZER_SRC) $(CURDIR)/main_stub.cpp
LIBTIFF_C_SRCS := $(wildcard $(LIBTIFF_SRC)/libtiff/*.c)

.PHONY: all clean ir

all: tiff_read_rgba_fuzzer

ir: $(INSTALL_DIR)/lib/libtiff.a
	mkdir -p $(IR_DIR)
	@set -e; for src in $(LIBTIFF_C_SRCS); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/lib_$${base%.*}.ll"; \
	    $(IR_CC) $(CFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(INSTALL_DIR)/include \
	        -I$(INSTALL_DIR)/build/libtiff \
	        -I$(LIBTIFF_SRC)/libtiff \
	        -o "$$out" "$$src" 2>/dev/null || true; done
	@set -e; for src in $(IR_SOURCES); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/$${base%.*}.ll"; \
	    echo "[ir] $$src -> $$out"; \
	    $(IR_CXX) $(CXXFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(INSTALL_DIR)/include \
	        -o "$$out" "$$src"; done

tiff_read_rgba_fuzzer: $(INSTALL_DIR)/lib/libtiff.a
	$(CXX) $(CXXFLAGS) -std=c++11 \
	    -I$(INSTALL_DIR)/include \
	    $(FUZZER_SRC) $(CURDIR)/main_stub.cpp \
	    -o $(CURDIR)/tiff_read_rgba_fuzzer \
	    $(INSTALL_DIR)/lib/libtiffxx.a \
	    $(INSTALL_DIR)/lib/libtiff.a \
	    -lz -ljpeg -llzma -lzstd

$(INSTALL_DIR)/lib/libtiff.a:
	cd $(LIBTIFF_SRC) && autoreconf -f -i
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && CFLAGS= CXXFLAGS= $(LIBTIFF_SRC)/configure \
	    CC="$(CC)" CXX="$(CXX)" \
	    --disable-shared --prefix="$(INSTALL_DIR)"
	CFLAGS= CXXFLAGS= $(MAKE) -C $(BUILD_DIR) -j$$(nproc 2>/dev/null || echo 1)
	CFLAGS= CXXFLAGS= $(MAKE) -C $(BUILD_DIR) install

clean:
	rm -rf $(INSTALL_DIR) $(CURDIR)/tiff_read_rgba_fuzzer

clean-ir:
	rm -rf $(IR_DIR)
