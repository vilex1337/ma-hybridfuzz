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

----
To be added
## Poppler
## OpenSSL
## PHP
## SQLite