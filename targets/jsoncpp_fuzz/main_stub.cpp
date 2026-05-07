// Minimal AFL++ forkserver driver for LLVMFuzzerTestOneInput targets.
// Avoids the persistent-mode / shmem conflict that arises when
// libAFLDriver.a is linked alongside afl-clang-fast++-instrumented code.
#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    size_t n = static_cast<size_t>(ftell(f));
    rewind(f);
    uint8_t* buf = static_cast<uint8_t*>(malloc(n > 0 ? n : 1));
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, n, f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, n);
    free(buf);
    return 0;
}
