OPENSSL_SRC := /targets/openssl

# OpenSSL builds fuzzers in-source; use a slug-stamped marker to avoid rebuilding.
_CXX_SLUG   := $(shell printf '%s' '$(CXX)' | tr '+/ @' '____')
BUILT_STAMP := $(OPENSSL_SRC)/.built_$(_CXX_SLUG)

# Primary fuzzer target (x509 certificate parsing).
FUZZER_BIN  := $(CURDIR)/x509

IR_DIR     ?= $(CURDIR)/ir
IR_CXX     ?= $(CXX)
IR_CC      ?= $(CC)
IR_SOURCES  := $(OPENSSL_SRC)/fuzz/x509.c
OPENSSL_C_SRCS := $(shell find $(OPENSSL_SRC)/crypto $(OPENSSL_SRC)/ssl -name '*.c' 2>/dev/null)

# Lightweight stamp: only Configure + build_generated (no AFL fuzz/x509 build).
IR_HEADERS_STAMP := $(OPENSSL_SRC)/.ir_headers

.PHONY: all clean ir

all: $(FUZZER_BIN)

$(IR_HEADERS_STAMP):
	cd $(OPENSSL_SRC) && CFLAGS= CXXFLAGS= ./Configure \
	    CC="$(IR_CC)" no-shared no-module \
	    -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION --debug
	CFLAGS= CXXFLAGS= $(MAKE) -C $(OPENSSL_SRC) build_generated
	touch $(IR_HEADERS_STAMP)

ir: $(IR_HEADERS_STAMP)
	mkdir -p $(IR_DIR)
	@for src in $(OPENSSL_C_SRCS); do \
	    rel=$$(echo "$$src" | sed "s|$(OPENSSL_SRC)/||"); \
	    base=$$(echo "$$rel" | tr '/' '_'); \
	    out="$(IR_DIR)/lib_$${base%.*}.ll"; \
	    $(IR_CC) $(CFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(OPENSSL_SRC)/include -I$(OPENSSL_SRC) \
	        -o "$$out" "$$src" 2>/dev/null || true; done
	@set -e; for src in $(IR_SOURCES); do \
	    base=$$(basename "$$src"); out="$(IR_DIR)/$${base%.*}.ll"; \
	    echo "[ir] $$src -> $$out"; \
	    $(IR_CC) $(CFLAGS) -S -emit-llvm -g -O0 -w \
	        -I$(OPENSSL_SRC)/include -I$(OPENSSL_SRC) \
	        -o "$$out" "$$src"; done

$(FUZZER_BIN): $(BUILT_STAMP)
	cp $(OPENSSL_SRC)/fuzz/x509 $(CURDIR)/x509

$(BUILT_STAMP):
	cd $(OPENSSL_SRC) && CFLAGS= CXXFLAGS= ./Configure \
	    CC="$(CC)" CXX="$(CXX)" \
	    enable-fuzz-afl no-shared no-module \
	    -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
	    --debug
	CFLAGS= CXXFLAGS= $(MAKE) -C $(OPENSSL_SRC) -j$$(nproc 2>/dev/null || echo 1) \
	    LDCMD="$(CXX) $(CXXFLAGS)" build_generated
	CFLAGS= CXXFLAGS= $(MAKE) -C $(OPENSSL_SRC) -j$$(nproc 2>/dev/null || echo 1) \
	    LDCMD="$(CXX) $(CXXFLAGS)" fuzz/x509
	touch $(BUILT_STAMP)

clean:
	rm -f $(BUILT_STAMP) $(CURDIR)/x509
	$(MAKE) -C $(OPENSSL_SRC) clean 2>/dev/null || true

clean-ir:
	rm -rf $(IR_DIR)
