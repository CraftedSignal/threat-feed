---
title: PHPSpreadsheet Denial of Service via Malformed XLS/OLE Sector Chain
slug: 2026-07-phpspreadsheet-dos
description: PhpSpreadsheet's OLE reader contains a denial-of-service vulnerability where it fails to detect cycles in attacker-controlled XLS/OLE sector chains, leading to infinite loops and memory exhaustion when parsing specially crafted, small malformed XLS/OLE files, which can cause PHP workers to crash and deny service to web applications processing untrusted spreadsheet uploads.
date: "2026-07-23T15:11:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - php
  - xls
  - ole
vendors:
  - PhpOffice
products:
  - PhpSpreadsheet (4.x series, versions >= 4.0.0, <= 5.8.0)
  - PhpSpreadsheet (3.x series, versions >= 3.3.0, <= 3.10.6)
  - PhpSpreadsheet (2.x series, versions >= 2.2.0, <= 2.4.6)
  - PhpSpreadsheet (2.x series, versions >= 2.0.0, <= 2.1.17)
  - PhpSpreadsheet (1.x series, versions <= 1.30.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A 1 KiB file can crash a PHP worker during `Xls::canRead()` or automatic file-type detection. This can deny service to web applications, queue workers, preview services, or document converters that process untrusted spreadsheet uploads.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xh5m-36r6-47m3
---

A denial-of-service vulnerability, identified as CVE-2026-59933, affects multiple versions of PhpSpreadsheet, a popular PHP library used for reading and writing spreadsheet files. The vulnerability stems from a flaw in the `OLERead::read()` function, which is responsible for parsing OLE (Object Linking and Embedding) structured storage files, such as older `.xls` format spreadsheets. The parser fails to detect cyclic references within attacker-controlled sector chains present in malformed OLE files, specifically in the small-block depot sector chain. This oversight causes the `read()` function to enter an infinite loop, continuously appending the same sector data until the PHP process exhausts its allocated memory, leading to a fatal error and application crash. This issue is critically reachable during automatic spreadsheet type detection (`Xls::canRead()`), meaning even an attempt to identify the file type can trigger the vulnerability, bypassing deeper validation checks. The vulnerability impacts web applications, queue workers, preview services, or document converters that process untrusted spreadsheet uploads, as a tiny 1 KiB malformed file can effectively take down a PHP worker.

## Attack Chain

1. An attacker crafts a small, malformed `.xls`/OLE file (e.g., 1 KiB in size).
2. The attacker manipulates the OLE header and allocation table values to create a self-loop in the small-block depot sector chain, specifically by setting a sector entry to point back to itself.
3. The victim's application, using the PhpSpreadsheet library, attempts to process an untrusted spreadsheet upload.
4. The application invokes `PhpOffice\PhpSpreadsheet\IOFactory::createReaderForFile()` or directly calls `PhpOffice\PhpSpreadsheet\Reader\Xls::canRead()` or `loadOLE()` to detect or load the file.
5. During this process, `PhpOffice\PhpSpreadsheet\Shared\OLERead::read()` is called to parse the OLE structure.
6. The `OLERead::read()` function encounters the maliciously crafted cyclic sector chain and enters an unbounded loop, continuously trying to read the same sector data.
7. The PHP process rapidly exhausts its memory limit, leading to a fatal memory exhaustion error and crashing the PHP worker handling the request.
8. The crash results in a denial of service for the web application or service, making it unavailable to legitimate users.

## Impact

A successful exploitation of CVE-2026-59933 can lead to a denial-of-service condition across various applications and services that utilize PhpSpreadsheet to process untrusted files. A file as small as 1 KiB can crash a PHP worker during file detection or loading, potentially rendering web applications, queue processing services, document preview services, or conversion tools unresponsive. This vulnerability bypasses typical validation checks because it triggers at the initial stage of file type detection. The observed damage includes PHP fatal errors due to memory exhaustion, leading to service disruption and unavailability for end-users. The potential number of victims is broad, encompassing any organization or developer using affected versions of PhpSpreadsheet in an environment that handles external spreadsheet uploads.

## Recommendation

* Prioritize patching all affected PhpSpreadsheet installations to a fixed version immediately. This addresses CVE-2026-59933 directly.
* Implement robust input validation and sanitization for all uploaded files, especially those processed by libraries like PhpSpreadsheet.
* Monitor PHP process memory usage closely, specifically for instances handling file uploads, to detect unusual spikes that could indicate an attempted denial-of-service attack related to CVE-2026-59933.
* Configure `memory_limit` in `php.ini` to a reasonable maximum for web workers to prevent single requests from consuming excessive resources, while understanding this mitigates symptoms, not the root cause.
