POPPLER_SRC  := /targets/poppler
FREETYPE_SRC := /targets/freetype
FUZZER_SRC   := $(CURDIR)/pdf_fuzzer.cc

_CXX_SLUG    := $(shell printf '%s' '$(CXX)' | tr '+/ @' '____')
FREETYPE_DIR := $(FREETYPE_SRC)/install_$(_CXX_SLUG)
POPPLER_DIR  := $(POPPLER_SRC)/build_$(_CXX_SLUG)

IR_DIR      ?= $(CURDIR)/ir
IR_CXX      ?= $(CXX)
IR_SOURCES   := $(FUZZER_SRC) $(CURDIR)/main_stub.cpp
POPPLER_CXX_SRCS := $(wildcard $(POPPLER_SRC)/poppler/*.cc)

.PHONY: all clean ir

all: pdf_fuzzer

ir: $(POPPLER_DIR)/libpoppler.a
	mkdir -p $(IR_DIR)
	@for src in $(POPPLER_CXX_SRCS); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/lib_$${base%.*}.ll"; \
	    $(IR_CXX) $(CXXFLAGS) -std=c++17 -S -emit-llvm -g -O0 -w \
	        -I$(FREETYPE_DIR)/include/freetype2 \
	        -I$(POPPLER_SRC) -I$(POPPLER_SRC)/poppler \
	        -I$(POPPLER_DIR) -I$(POPPLER_DIR)/poppler \
	        -I$(POPPLER_SRC)/cpp \
	        -o "$$out" "$$src" 2>/dev/null || true; done
	@set -e; for src in $(IR_SOURCES); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/$${base%.*}.ll"; \
	    echo "[ir] $$src -> $$out"; \
	    $(IR_CXX) $(CXXFLAGS) -std=c++17 -S -emit-llvm -g -O0 -w \
	        -I$(FREETYPE_DIR)/include/freetype2 \
	        -I$(POPPLER_SRC) -I$(POPPLER_SRC)/poppler \
	        -I$(POPPLER_DIR) -I$(POPPLER_DIR)/poppler \
	        -I$(POPPLER_SRC)/cpp \
	        -o "$$out" "$$src"; done

pdf_fuzzer: $(POPPLER_DIR)/libpoppler.a
	$(CXX) $(CXXFLAGS) -std=c++17 \
	    -I$(FREETYPE_DIR)/include/freetype2 \
	    -I$(POPPLER_SRC) -I$(POPPLER_SRC)/poppler \
	    -I$(POPPLER_DIR) -I$(POPPLER_DIR)/poppler \
	    -I$(POPPLER_SRC)/cpp \
	    $(FUZZER_SRC) $(CURDIR)/main_stub.cpp \
	    -o $(CURDIR)/pdf_fuzzer \
	    $(POPPLER_DIR)/libpoppler.a \
	    $(FREETYPE_DIR)/lib/libfreetype.a \
	    -ljpeg -lz -lpng -lopenjp2 -llcms2 -lfontconfig -ltiff -lpthread -lm

$(POPPLER_DIR)/libpoppler.a: $(FREETYPE_DIR)/lib/libfreetype.a
	mkdir -p $(POPPLER_DIR)
	cd $(POPPLER_DIR) && CFLAGS= CXXFLAGS= cmake \
	    -DCMAKE_C_COMPILER="$(CC)" \
	    -DCMAKE_CXX_COMPILER="$(CXX)" \
	    -DCMAKE_BUILD_TYPE=debug \
	    -DBUILD_SHARED_LIBS=OFF \
	    -DENABLE_UNSTABLE_API_ABI_HEADERS=ON \
	    -DENABLE_DCTDECODER=libjpeg \
	    -DENABLE_LIBOPENJPEG=openjpeg2 \
	    -DFREETYPE_INCLUDE_DIRS="$(FREETYPE_DIR)/include/freetype2" \
	    -DFREETYPE_LIBRARY="$(FREETYPE_DIR)/lib/libfreetype.a" \
	    -DCMAKE_DISABLE_FIND_PACKAGE_Qt5Core=ON \
	    -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Core=ON \
	    $(POPPLER_SRC)
	CFLAGS= CXXFLAGS= $(MAKE) -C $(POPPLER_DIR) -j$$(nproc 2>/dev/null || echo 1) poppler

$(FREETYPE_DIR)/lib/libfreetype.a:
	mkdir -p $(FREETYPE_DIR)/build
	cd $(FREETYPE_DIR)/build && CFLAGS= CXXFLAGS= cmake \
	    -DCMAKE_C_COMPILER="$(CC)" \
	    -DCMAKE_CXX_COMPILER="$(CXX)" \
	    -DCMAKE_BUILD_TYPE=Release \
	    -DBUILD_SHARED_LIBS=OFF \
	    -DCMAKE_INSTALL_PREFIX="$(FREETYPE_DIR)" \
	    -DFT_WITH_ZLIB=OFF \
	    -DFT_WITH_PNG=OFF \
	    -DFT_WITH_HARFBUZZ=OFF \
	    -DFT_WITH_BZIP2=OFF \
	    -DFT_WITH_BROTLI=OFF \
	    -DCMAKE_DISABLE_FIND_PACKAGE_BZip2=ON \
	    -DCMAKE_DISABLE_FIND_PACKAGE_PNG=ON \
	    -DCMAKE_DISABLE_FIND_PACKAGE_HarfBuzz=ON \
	    -DCMAKE_DISABLE_FIND_PACKAGE_BrotliDec=ON \
	    $(FREETYPE_SRC)
	CFLAGS= CXXFLAGS= $(MAKE) -C $(FREETYPE_DIR)/build -j$$(nproc 2>/dev/null || echo 1)
	CFLAGS= CXXFLAGS= $(MAKE) -C $(FREETYPE_DIR)/build install

clean:
	rm -rf $(POPPLER_DIR) $(FREETYPE_DIR) $(CURDIR)/pdf_fuzzer

clean-ir:
	rm -rf $(IR_DIR)
