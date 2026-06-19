# Bug list
_Format : CVE name: Description - class_
## Libpng

1. CVE-2019-7317: png_image_free in png.c in libpng has a use-after-free because png_image_free_function is called under png_safe_execute - Use-after-free .

2. CVE-2015-0973: Buffer overflow in the png_read_IDAT_data function in pngrutil.c in libpng allows context-dependent attackers to execute arbitrary code via IDAT data with a large width - Integer overflow

3. CVE-2015-8472: Buffer overflow in the png_set_PLTE function in libpng allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a small bit-depth value in an IHDR (aka image header) chunk in a PNG image - API inconsistency.

4. CVE-2013-6954: The png_do_expand_palette function in libpng allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via (1) a PLTE chunk of zero bytes or (2) a NULL palette, related to pngrtran.c and pngset.c - 0 pointer dereference.

## LibTIFF
1. CVE-2016-9535: tif_predict.h and tif_predict.c have assertions that can lead to assertion failures in debug mode, or buffer overflows in release mode, when dealing with unusual tile size like YCbCr with subsampling - Heap buffer overflow

2. CVE-2016-5314: Buffer overflow in the PixarLogDecode function in tif_pixarlog.c in LibTIFF 4.0.6 and earlier allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted TIFF image - Heap buffer overflow

3. CVE-2019-7663: An Invalid Address dereference was discovered in TIFFWriteDirectoryTagTransferfunction in libtiff/tif_dirwrite.c, affecting the cpSeparateBufToContigBuf function in tiffcp.c - 0 pointer dereference.

4. CVE-2016-10269: LibTIFF allows remote attackers to cause a denial of service (heap-based buffer over-read) or possibly have unspecified other impact via a crafted TIFF image, related to "READ of size 512" and libtiff/tif_unix.c:340:2 - OOB Read.

5. CVE-2018-7456: A NULL Pointer Dereference occurs in the function TIFFPrintDirectory in tif_print.c when using the tiffinfo tool to print crafted TIFF information - 0 pointer dereference

6. CVE-2018-18557: LibTIFF decodes arbitrarily-sized JBIG into a buffer, ignoring the buffer size, which leads to a tif_jbig.c JBIGDecode out-of-bounds write - OOB Write.

## Libxml2
1. CVE-2017-9047: A buffer overflow was discovered. The function xmlSnprintfElementContent in valid.c is supposed to recursively dump the element content definition into a char buffer 'buf' of size 'size'. The variable len is assigned strlen(buf). If the content->type is XML_ELEMENT_CONTENT_ELEMENT, then (i) the content->prefix is appended to buf (if it actually fits) whereupon (ii) content->name is written to the buffer. However, the check for whether the content->name actually fits also uses 'len' rather than the updated buffer length strlen(buf). This allows us to write about "size" many bytes beyond the allocated memory - Buffer overflow.

2. CVE-2017-0663: A remote code execution vulnerability in libxml2 in valid.c while processing xmlAddID could enable an attacker using a specially crafted file to execute arbitrary code within the context of an unprivileged process - Type confusion. 

3. CVE-2017-7375: A flaw in libxml2 allows remote XML entity inclusion with default parser flags (i.e., when the caller did not request entity substitution, DTD validation, external DTD subset loading, or default DTD attributes) in parser.c - XML external entity.

4. CVE-2016-1836: Use-after-free vulnerability in the xmlDictComputeFastKey function in libxml2  allows remote attackers to cause a denial of service via a crafted XML document - Use after free.

## Poppler
1. CVE-2019-14494: An issue was discovered in Poppler through 0.78.0. There is a divide-by-zero error in the function SplashOutputDev::tilingPatternFill at SplashOutputDev.cc - Divide by zero.

2. CVE-2019-9200: There is a heap-based buffer over-read in the function ImageStream::getLine() located in Stream.cc, triggered by mishandling of a negative number of characters returned by the underlying decode filter - Heap buffer overflow (OOB read).

3. CVE-2018-20650: A reachable Object::dictLookup assertion in Poppler 0.72.0 allows attackers to cause a denial of service due to the lack of a check for the dict data type, as demonstrated by use of the FileSpec class in FileSpec.cc - Type confusion.

4. CVE-2017-9776: A heap-based buffer over-read vulnerability was found in the function JBIG2Bitmap::combine() in JBIG2Stream.cc, related to extraneous JBIG2 symbol dictionary or text region data - Heap buffer overflow (OOB read).

## OpenSSL
1. CVE-2016-2108: The ASN.1 implementation in OpenSSL allows remote attackers to execute arbitrary code or cause a denial of service (buffer underflow and memory corruption) via an ANY field in crafted serialized data, aka the "negative zero" issue - Memory corruption.

2. CVE-2016-2109: The asn1_d2i_read_bio function in crypto/asn1/a_d2i_fp.c allows remote attackers to cause a denial of service (memory consumption) via a short invalid encoding - Memory exhaustion / denial of service.

3. CVE-2016-0797: Multiple integer overflows in crypto/bn/bn_print.c allow remote attackers to cause a denial of service (heap memory corruption or NULL pointer dereference) via crafted data that triggers an integer overflow in BN_dec2bn / BN_hex2bn - Integer overflow.

4. CVE-2016-7052: crypto/x509/x509_vfy.c allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via a malformed X.509 certificate with crafted CRL distribution points - Null pointer dereference.

## PHP
1. CVE-2019-11034: An out-of-bounds read can occur in exif_process_IFD_in_MAKERNOTE in ext/exif/exif.c via crafted EXIF data in a JPEG file - OOB Read.

2. CVE-2019-9641: exif_process_IFD_in_TIFF in ext/exif/exif.c performs a bounds check using an addition that can overflow when the IFD directory offset is near SIZE_MAX, bypassing the check - Integer overflow.

3. CVE-2017-11362: ext/intl/msgformat/msgformat_parse.c mishandles the msgfmt_parse_message function call with a long locale name argument, allowing a denial of service or possibly other impact - Stack buffer overflow.

4. CVE-2018-7584: There is a stack-based buffer under-read while parsing an HTTP response in the php_stream_url_wrap_http_ex function in ext/standard/http_fopen_wrapper.c - Stack buffer underflow.

## SQLite
1. CVE-2019-9936: Running fts5 prefix queries inside a transaction could trigger a heap-based buffer over-read in fts5HashEntrySort in ext/fts5/fts5_hash.c, which may lead to an information leak - Heap buffer overflow (OOB read).

2. CVE-2019-19244: sqlite3Select in select.c allows a crash if a sub-select uses both DISTINCT and window functions, and also has certain ORDER BY usage - Null pointer dereference.

3. CVE-2013-7443: Buffer overflow in the skip-scan optimization (whereLoopAddBtreeIndex in where.c) allows remote attackers to cause a denial of service via crafted SQL statements - Heap buffer overflow.

4. CVE-2019-19959: The zipfile virtual table extension (ext/misc/zipfile.c) uses a stale entry-name length instead of recomputing it with strlen() after normalizing the name, leading to a heap-based buffer overflow - Heap buffer overflow.