PHP_SRC     := /targets/php
ONIG_SRC    := /targets/oniguruma

_CXX_SLUG   := $(shell printf '%s' '$(CXX)' | tr '+/ @' '____')
ONIG_DIR    := $(ONIG_SRC)/install_$(_CXX_SLUG)
BUILT_STAMP := $(PHP_SRC)/.built_$(_CXX_SLUG)

FUZZER_BIN  := $(CURDIR)/php-fuzz-json

IR_DIR     ?= $(CURDIR)/ir
IR_CXX     ?= $(CXX)
IR_CC      ?= $(CC)
IR_SOURCES  := $(PHP_SRC)/sapi/fuzzer/fuzzer-sapi.c \
               $(PHP_SRC)/sapi/fuzzer/fuzzer-json.c
PHP_IR_SRCS := $(wildcard $(PHP_SRC)/ext/json/*.c) \
               $(wildcard $(PHP_SRC)/Zend/*.c) \
               $(wildcard $(PHP_SRC)/main/*.c)

.PHONY: all clean ir

all: $(FUZZER_BIN)

ir: $(BUILT_STAMP)
	mkdir -p $(IR_DIR)
	@for src in $(PHP_IR_SRCS); do \
	    base=$$(basename "$$src"); dir=$$(basename $$(dirname "$$src")); \
	    out="$(IR_DIR)/lib_$${dir}_$${base%.*}.ll"; \
	    $(IR_CC) $(CFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(PHP_SRC) -I$(PHP_SRC)/main -I$(PHP_SRC)/TSRM \
	        -I$(PHP_SRC)/Zend -I$(PHP_SRC)/ext \
	        -I$(ONIG_DIR)/include \
	        -o "$$out" "$$src" 2>/dev/null || true; done
	@set -e; for src in $(IR_SOURCES); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/$${base%.*}.ll"; \
	    echo "[ir] $$src -> $$out"; \
	    $(IR_CC) $(CFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(PHP_SRC) -I$(PHP_SRC)/main -I$(PHP_SRC)/TSRM \
	        -I$(PHP_SRC)/Zend -I$(PHP_SRC)/ext \
	        -I$(ONIG_DIR)/include \
	        -o "$$out" "$$src"; done

$(FUZZER_BIN): $(BUILT_STAMP)
	cp $(PHP_SRC)/sapi/fuzzer/php-fuzz-json $(CURDIR)/php-fuzz-json

$(BUILT_STAMP): $(ONIG_DIR)/lib/libonig.a
	cd $(PHP_SRC) && ./buildconf --force
	cd $(PHP_SRC) && CFLAGS= CXXFLAGS= ./configure \
	    CC="$(CC)" CXX="$(CXX)" \
	    --disable-all \
	    --enable-fuzzer \
	    --enable-exif \
	    --enable-mbstring \
	    --without-pcre-jit \
	    --disable-phpdbg \
	    --disable-cgi \
	    --with-pic \
	    ONIG_CFLAGS="-I$(ONIG_DIR)/include" \
	    ONIG_LIBS="-L$(ONIG_DIR)/lib -lonig"
	CFLAGS= CXXFLAGS= $(MAKE) -C $(PHP_SRC) -j$$(nproc 2>/dev/null || echo 1)
	touch $(BUILT_STAMP)

$(ONIG_DIR)/lib/libonig.a:
	cd $(ONIG_SRC) && autoreconf -f -i
	mkdir -p $(ONIG_DIR)/build
	cd $(ONIG_DIR)/build && CFLAGS= CXXFLAGS= $(ONIG_SRC)/configure \
	    CC="$(CC)" CXX="$(CXX)" \
	    --prefix="$(ONIG_DIR)" --disable-shared
	CFLAGS= CXXFLAGS= $(MAKE) -C $(ONIG_DIR)/build -j$$(nproc 2>/dev/null || echo 1)
	CFLAGS= CXXFLAGS= $(MAKE) -C $(ONIG_DIR)/build install

clean:
	rm -f $(BUILT_STAMP) $(CURDIR)/php-fuzz-json
	$(MAKE) -C $(PHP_SRC) clean 2>/dev/null || true

clean-ir:
	rm -rf $(IR_DIR)
