SQLITE3_SRC := /targets/sqlite3
FUZZER_C    := $(SQLITE3_SRC)/test/ossfuzz.c
AMALGAM     := $(SQLITE3_SRC)/sqlite3.c

_CXX_SLUG   := $(shell printf '%s' '$(CXX)' | tr '+/ @' '____')
BUILD_DIR   := $(SQLITE3_SRC)/build_$(_CXX_SLUG)

SQLITE_DEFS := \
    -DSQLITE_MAX_LENGTH=128000000 \
    -DSQLITE_MAX_SQL_LENGTH=128000000 \
    -DSQLITE_MAX_MEMORY=25000000 \
    -DSQLITE_DEBUG=1 \
    -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
    -DSQLITE_MAX_PAGE_COUNT=16384

IR_DIR     ?= $(CURDIR)/ir
IR_CXX     ?= $(CXX)
IR_CC      ?= $(CC)
IR_SOURCES  := $(FUZZER_C) $(CURDIR)/main_stub.cpp

.PHONY: all clean ir

all: sqlite3_fuzz

ir: $(AMALGAM)
	mkdir -p $(IR_DIR)
	$(IR_CC) $(CFLAGS) -S -emit-llvm -g -O0 -w \
	    $(SQLITE_DEFS) \
	    -I$(SQLITE3_SRC) \
	    -o "$(IR_DIR)/sqlite3_amalgam.ll" $(AMALGAM)
	$(IR_CC) $(CFLAGS) -S -emit-llvm -g -O0 -w \
	    $(SQLITE_DEFS) \
	    -I$(SQLITE3_SRC) \
	    -o "$(IR_DIR)/ossfuzz.ll" $(FUZZER_C)
	$(IR_CXX) $(CXXFLAGS) -S -emit-llvm -g -O0 -w \
	    -o "$(IR_DIR)/main_stub.ll" $(CURDIR)/main_stub.cpp

FUZZER_OBJ := $(BUILD_DIR)/ossfuzz.o

sqlite3_fuzz: $(BUILD_DIR)/sqlite3.o $(FUZZER_OBJ)
	$(CXX) $(CXXFLAGS) \
	    $(CURDIR)/main_stub.cpp \
	    $(FUZZER_OBJ) \
	    $(BUILD_DIR)/sqlite3.o \
	    -o $(CURDIR)/sqlite3_fuzz \
	    -pthread -ldl -lm

$(FUZZER_OBJ): $(BUILD_DIR)/sqlite3.o
	$(CC) $(CFLAGS) \
	    -I$(SQLITE3_SRC) $(SQLITE_DEFS) \
	    -c $(FUZZER_C) -o $(FUZZER_OBJ)

$(BUILD_DIR)/sqlite3.o: $(AMALGAM)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) \
	    $(SQLITE_DEFS) \
	    -I$(SQLITE3_SRC) \
	    -c $(AMALGAM) -o $(BUILD_DIR)/sqlite3.o

$(AMALGAM):
	cd $(SQLITE3_SRC) && CFLAGS= CXXFLAGS= ./configure \
	    CC="$(CC)" --disable-shared --enable-rtree
	CFLAGS= CXXFLAGS= ASAN_OPTIONS=detect_leaks=0 \
	    $(MAKE) -C $(SQLITE3_SRC) -j$$(nproc 2>/dev/null || echo 1) sqlite3.c

clean:
	rm -rf $(BUILD_DIR) $(CURDIR)/sqlite3_fuzz

clean-ir:
	rm -rf $(IR_DIR)
