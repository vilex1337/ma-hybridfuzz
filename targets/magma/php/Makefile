PHP_SRC     := /targets/php
ONIG_SRC    := /targets/oniguruma

_CXX_SLUG   := $(shell printf '%s' '$(CXX)' | tr '+/ @' '____')
ONIG_DIR    := $(ONIG_SRC)/install_$(_CXX_SLUG)
BUILT_STAMP := $(PHP_SRC)/.built_$(_CXX_SLUG)

FUZZER_BINS := $(CURDIR)/php-fuzz-json \
               $(CURDIR)/php-fuzz-parser \
               $(CURDIR)/php-fuzz-exif

IR_DIR              ?= $(CURDIR)/ir
IR_CONFIGURED_STAMP := $(PHP_SRC)/.ir_configured
IR_CXX     ?= $(CXX)
IR_CC      ?= $(CC)
IR_SOURCES  := $(PHP_SRC)/sapi/fuzzer/fuzzer-sapi.c \
               $(PHP_SRC)/sapi/fuzzer/fuzzer-json.c
PHP_IR_SRCS := $(wildcard $(PHP_SRC)/ext/json/*.c) \
               $(wildcard $(PHP_SRC)/Zend/*.c) \
               $(wildcard $(PHP_SRC)/main/*.c)

.PHONY: all clean ir

all: $(FUZZER_BINS)

ir: $(IR_CONFIGURED_STAMP)
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

$(CURDIR)/php-fuzz-json: $(BUILT_STAMP)
	cp $(PHP_SRC)/sapi/fuzzer/php-fuzz-json $(CURDIR)/php-fuzz-json

$(CURDIR)/php-fuzz-parser: $(BUILT_STAMP)
	cp $(PHP_SRC)/sapi/fuzzer/php-fuzz-parser $(CURDIR)/php-fuzz-parser

$(CURDIR)/php-fuzz-exif: $(BUILT_STAMP)
	cp $(PHP_SRC)/sapi/fuzzer/php-fuzz-exif $(CURDIR)/php-fuzz-exif

$(IR_CONFIGURED_STAMP): $(ONIG_DIR)/lib/libonig.a
	@if ! test -f "$(PHP_SRC)/main/php_config.h"; then \
	    echo "[ir] php_config.h not found — configuring PHP to generate it..."; \
	    cd $(PHP_SRC) && ./buildconf --force; \
	    cd $(PHP_SRC) && CC="$(IR_CC)" CXX="$(IR_CXX)" ./configure \
	        --disable-all \
	        --enable-fuzzer \
	        --enable-exif \
	        --enable-mbstring \
	        --without-pcre-jit \
	        --disable-phpdbg \
	        --disable-cgi \
	        --with-pic \
	        ONIG_CFLAGS="-I$(ONIG_DIR)/include" \
	        ONIG_LIBS="-L$(ONIG_DIR)/lib -lonig"; \
	fi
	touch $(IR_CONFIGURED_STAMP)

$(BUILT_STAMP): $(ONIG_DIR)/lib/libonig.a
	cd $(PHP_SRC) && ./buildconf --force
	cd $(PHP_SRC) && CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" ./configure \
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
	$(MAKE) -C $(PHP_SRC) -j$$(nproc 2>/dev/null || echo 1)
	touch $(BUILT_STAMP)
	touch $(IR_CONFIGURED_STAMP)

$(ONIG_DIR)/lib/libonig.a:
	cd $(ONIG_SRC) && autoreconf -f -i
	mkdir -p $(ONIG_DIR)/build
	cd $(ONIG_DIR)/build && CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" $(ONIG_SRC)/configure \
	    CC="$(CC)" CXX="$(CXX)" \
	    --prefix="$(ONIG_DIR)" --disable-shared
	$(MAKE) -C $(ONIG_DIR)/build -j$$(nproc 2>/dev/null || echo 1)
	$(MAKE) -C $(ONIG_DIR)/build install

clean:
	rm -f $(BUILT_STAMP) $(CURDIR)/php-fuzz-json $(CURDIR)/php-fuzz-parser $(CURDIR)/php-fuzz-exif
	$(MAKE) -C $(PHP_SRC) clean 2>/dev/null || true

clean-ir:
	rm -rf $(IR_DIR)
