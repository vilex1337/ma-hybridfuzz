// Minimal AFL++ forkserver driver for LLVMFuzzerTestOneInput targets.
// Avoids the persistent-mode / shmem conflict that arises when
// libAFLDriver.a is linked alongside afl-clang-fast++-instrumented code.
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#ifdef MA_COVERAGE_BUILD
// CoverageChecker probes crash-inducing seeds (e.g. inputs from AFL's
// crashes/ dir) to see which functions they reach. -fprofile-instr-generate
// only flushes counters at normal exit, so a seed that segfaults/aborts the
// process loses its coverage data. Trapping the fatal signal and flushing
// the profile before re-raising lets those seeds register their coverage.
#include <csignal>
extern "C" int __llvm_profile_write_file(void);

static void ma_flush_profile_and_reraise(int sig) {
    __llvm_profile_write_file();
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
#ifdef MA_COVERAGE_BUILD
    std::signal(SIGSEGV, ma_flush_profile_and_reraise);
    std::signal(SIGABRT, ma_flush_profile_and_reraise);
    std::signal(SIGBUS, ma_flush_profile_and_reraise);
    std::signal(SIGFPE, ma_flush_profile_and_reraise);
#endif
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
