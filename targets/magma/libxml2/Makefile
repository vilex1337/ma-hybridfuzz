LIBXML2_SRC := /targets/libxml2
FUZZER_SRC  := $(CURDIR)/libxml2_xml_read_memory_fuzzer.cc

_CXX_SLUG   := $(shell printf '%s' '$(CXX)' | tr '+/ @' '____')
INSTALL_DIR := $(LIBXML2_SRC)/install_$(_CXX_SLUG)
BUILD_DIR   := $(INSTALL_DIR)/build

IR_DIR     ?= $(CURDIR)/ir
IR_CXX     ?= $(CXX)
IR_CC      ?= $(CC)
IR_SOURCES  := $(FUZZER_SRC) $(CURDIR)/main_stub.cpp
LIBXML2_C_SRCS := $(wildcard $(LIBXML2_SRC)/*.c)

.PHONY: all clean ir

all: libxml2_xml_read_memory_fuzzer

ir: $(INSTALL_DIR)/lib/libxml2.a
	mkdir -p $(IR_DIR)
	@for src in $(LIBXML2_C_SRCS); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/lib_$${base%.*}.ll"; \
	    $(IR_CC) $(CFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(LIBXML2_SRC) -I$(LIBXML2_SRC)/include \
	        -I$(INSTALL_DIR)/include/libxml2 \
	        -I$(BUILD_DIR) \
	        -o "$$out" "$$src" 2>/dev/null || true; done
	@set -e; for src in $(IR_SOURCES); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/$${base%.*}.ll"; \
	    echo "[ir] $$src -> $$out"; \
	    $(IR_CXX) $(CXXFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(INSTALL_DIR)/include/libxml2 -I$(CURDIR) \
	        -o "$$out" "$$src"; done

libxml2_xml_read_memory_fuzzer: $(INSTALL_DIR)/lib/libxml2.a
	$(CXX) $(CXXFLAGS) -std=c++11 \
	    -I$(INSTALL_DIR)/include/libxml2 -I$(CURDIR) \
	    $(FUZZER_SRC) $(CURDIR)/main_stub.cpp \
	    -o $(CURDIR)/libxml2_xml_read_memory_fuzzer \
	    $(INSTALL_DIR)/lib/libxml2.a -lz -llzma

$(INSTALL_DIR)/lib/libxml2.a:
	cd $(LIBXML2_SRC) && autoreconf -f -i
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" $(LIBXML2_SRC)/configure \
	    CC="$(CC)" CXX="$(CXX)" \
	    --without-http --without-python --with-lzma=yes \
	    --without-threads --disable-shared \
	    --prefix="$(INSTALL_DIR)"
	$(MAKE) -C $(BUILD_DIR) -j$$(nproc 2>/dev/null || echo 1)
	$(MAKE) -C $(BUILD_DIR) install

clean:
	rm -rf $(INSTALL_DIR) $(CURDIR)/libxml2_xml_read_memory_fuzzer

clean-ir:
	rm -rf $(IR_DIR)
