// Minimal PDF fuzzing harness for poppler.
// Based on the OSS-Fuzz poppler target.
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "GlobalParams.h"
#include "PDFDoc.h"
#include "PDFDocFactory.h"
#include "goo/GooString.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;

    globalParams = std::make_unique<GlobalParams>();
    globalParams->setErrQuiet(true);

    auto *mem = new MemStream(
        reinterpret_cast<const char*>(data), 0, size, Object(objNull));
    auto doc = std::make_unique<PDFDoc>(mem);

    if (doc->isOk() && doc->getNumPages() > 0) {
        // Exercise the parser by reading a few pages.
        int pages = std::min(doc->getNumPages(), 3);
        for (int i = 1; i <= pages; i++) {
            doc->getPage(i);
        }
    }

    globalParams.reset();
    return 0;
}
