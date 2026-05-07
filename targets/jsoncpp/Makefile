JSONCPP_DIR := $(CURDIR)
BUILD_DIR   := $(JSONCPP_DIR)/cmake_build

# Locate libAFLDriver.a — AFL++ installs it in different paths depending on version.
AFL_DRIVER := $(shell find /usr/local/lib/afl /AFLplusplus /usr/local/lib 2>/dev/null \
                  -name "libAFLDriver.a" 2>/dev/null | head -1)

.PHONY: all clean

all: jsoncpp_fuzzer

# Step 2: compile fuzz harness, link against jsoncpp library and AFL driver.
jsoncpp_fuzzer: $(BUILD_DIR)/lib/libjsoncpp.a
	$(CXX) $(CXXFLAGS) \
	    -I$(JSONCPP_DIR)/include \
	    -I$(JSONCPP_DIR)/src/test_lib_json \
	    $(JSONCPP_DIR)/src/test_lib_json/fuzz.cpp \
	    $(AFL_DRIVER) \
	    -o $(JSONCPP_DIR)/jsoncpp_fuzzer \
	    $(BUILD_DIR)/lib/libjsoncpp.a

# Step 1: build jsoncpp static library via CMake.
$(BUILD_DIR)/lib/libjsoncpp.a:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake \
	    -DCMAKE_C_COMPILER="$(CC)" \
	    -DCMAKE_CXX_COMPILER="$(CXX)" \
	    -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF \
	    -DJSONCPP_WITH_TESTS=OFF \
	    -DBUILD_SHARED_LIBS=OFF \
	    -G "Unix Makefiles" \
	    $(JSONCPP_DIR)
	$(MAKE) -C $(BUILD_DIR) -j$(shell nproc 2>/dev/null || echo 1)

clean:
	rm -rf $(BUILD_DIR) jsoncpp_fuzzer
