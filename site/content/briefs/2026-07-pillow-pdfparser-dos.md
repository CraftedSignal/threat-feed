---
title: Pillow Decompression Bomb DoS via PdfParser.PdfStream.decode()
slug: 2026-07-pillow-pdfparser-dos
description: A denial-of-service vulnerability (CVE-2026-59200) exists in Pillow's `PdfParser.PdfStream.decode()` function across versions 5.1.0 to 12.2.x, allowing an unauthenticated attacker to craft a malicious PDF file that, when processed by a vulnerable application, triggers excessive memory allocation (e.g., a ~950 KB file expanding to 1 GB), leading to server Out-of-Memory termination or severe service degradation.
date: "2026-07-20T23:12:09Z"
lastmod: "2026-07-22T01:01:12Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
  - cpe:2.3:a:pdfminer:pdfminer.six:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=11AD219D-F4A5-5008-908F-FEF87CC3F5A8&utm_source=rss&utm_medium=rss
tags:
  - denial-of-service
  - vulnerability
  - python
  - library
  - pdf
vendors:
  - Pillow
  - Pdfminer
products:
  - Pillow (>= 5.1.0, < 12.3.0)
  - pdfminer.six < 20251107
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker who can submit a PDF for processing can exhaust all available server memory with a ~950 KB file, causing OOM termination or service degradation affecting all concurrent users.
    confidence_band: high
cves:
  - id: CVE-2026-59200
    cvss: 7.5
    epss: 0.0035
  - id: CVE-2025-64512
    cvss: 8.6
    epss: 0.00314
references:
  - https://github.com/advisories/GHSA-jjj6-mw9f-p565
  - https://sploitus.com/exploit?id=11AD219D-F4A5-5008-908F-FEF87CC3F5A8&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=11AD219D-F4A5-5008-908F-FEF87CC3F5A8
  - type: url
    value: https://github.com/MehdiChyhab/CVE-2025-64512-exploit.git
ioc_counts:
  url: 2
updates:
  - at: "2026-07-22T01:01:12Z"
    level: L2
    summary: poc_available; added CVE-2025-64512
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=11AD219D-F4A5-5008-908F-FEF87CC3F5A8&utm_source=rss&utm_medium=rss
---

A denial-of-service (DoS) vulnerability, tracked as CVE-2026-59200, has been identified in Pillow, a widely used Python imaging library. Specifically, the `PdfParser.PdfStream.decode()` function in `PdfParser.py` incorrectly utilizes the `Length` field from a PDF stream as the `bufsize` parameter for Python's `zlib.decompress()`. While `bufsize` is intended as an initial buffer hint, it does not impose a maximum memory limit, allowing `zlib.decompress()` to expand memory until the entire decompressed result is produced. An unauthenticated attacker can exploit this by crafting a specially designed PDF file containing a highly compressed FlateDecode stream. When an application using Pillow's `PdfParser` processes such a file, the malicious stream decompresses into a significantly larger memory footprint (e.g., a ~950 KB file can expand to 1 GB), leading to Out-of-Memory (OOM) errors and service termination or severe degradation for the host system. This vulnerability affects Pillow versions greater than or equal to 5.1.0 and less than 12.3.0.

## Attack Chain

1. An attacker crafts a malicious PDF file containing a highly compressed FlateDecode stream.
2. The `Length` or `DL` field within the PDF stream's dictionary is set to a value reflecting the compressed stream size.
3. The attacker delivers the malicious PDF to a target application that uses `PIL.PdfParser.PdfParser` to process untrusted PDF files.
4. The target application opens and parses the untrusted PDF using an instance of `PdfParser.PdfParser`.
5. The application attempts to access a compressed stream object from the parsed PDF, triggering a call to `PdfStream.decode()`.
6. Inside `PdfStream.decode()`, the `zlib.decompress()` function is invoked, passing the potentially large value from the PDF stream's `Length` field as its `bufsize` parameter.
7. `zlib.decompress()` proceeds to expand the highly compressed stream, allocating memory far exceeding the compressed file size (e.g., a 95 KB file expanding to 100 MB or a 950 KB file expanding to 1 GB).
8. This excessive memory allocation exhausts the available server memory, leading to an Out-of-Memory (OOM) error, process termination, or severe service degradation for the target application, effectively causing a denial of service.

## Impact

This vulnerability directly leads to a denial-of-service condition. Any application that uses Pillow's `PIL.PdfParser.PdfParser` module to process untrusted PDF files is susceptible. An unauthenticated attacker can exploit this by submitting a relatively small (e.g., ~950 KB) malicious PDF file, which, when decompressed, consumes gigabytes of memory. This resource exhaustion will cause the server or application process to terminate due to Out-of-Memory errors or experience significant performance degradation, affecting all users and services relying on the vulnerable application. There is no specific victim count available, but any sector using Python applications that process untrusted PDFs with affected Pillow versions is at risk.

## Recommendation

* Immediately patch Pillow installations (affected versions >= 5.1.0, < 12.3.0) to version 12.3.0 or higher to address CVE-2026-59200.
* Implement resource monitoring for Python applications that process untrusted PDF files, focusing on memory usage spikes, to detect potential denial-of-service attempts.
* Review any custom code interacting with `PIL.PdfParser.PdfParser` and consider implementing explicit size checks for decompressed data, similar to the `MAX_DECOMPRESS_BYTES` example provided in the source material, to prevent unbounded memory allocation.
