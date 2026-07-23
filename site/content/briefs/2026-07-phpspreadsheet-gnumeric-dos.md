---
title: PhpSpreadsheet Gnumeric Reader Unbounded Gzip Expansion Leads to Denial of Service
slug: 2026-07-phpspreadsheet-gnumeric-dos
description: The PhpOffice PhpSpreadsheet library is vulnerable to a denial of service (DoS) attack, identified as CVE-2026-59932, where its Gnumeric reader processes attacker-supplied `.gnumeric` files containing gzipped content without enforcing a decompressed-size limit, causing memory exhaustion and application crashes.
date: "2026-07-23T15:02:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - phpspreadsheet
  - php
  - ghsa
  - software-supply-chain
vendors:
  - PhpOffice
products:
  - PhpSpreadsheet (<= 1.30.5)
  - PhpSpreadsheet (>= 2.0.0, <= 2.1.17)
  - PhpSpreadsheet (>= 2.2.0, <= 2.4.6)
  - PhpSpreadsheet (>= 3.3.0, <= 3.10.6)
  - PhpSpreadsheet (>= 4.0.0, <= 5.8.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A small .gnumeric upload can crash a PHP worker during spreadsheet type detection or import. This can cause denial of service in web applications, queue workers, preview services, document converters, or any service that runs PhpSpreadsheet against untrusted spreadsheet files.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2mrg-gjxq-2gvr
---

The PhpOffice PhpSpreadsheet library, a widely used PHP library for reading and writing spreadsheet files, contains a critical vulnerability (CVE-2026-59932) in its Gnumeric file reader component. When processing an attacker-supplied `.gnumeric` file, the `Gnumeric::canRead()` function and subsequent processing paths invoke `gzdecode()` on gzipped contents without implementing a maximum decompressed-size limit. This allows a small, specially crafted compressed `.gnumeric` file to expand significantly, consuming excessive memory and leading to a PHP fatal error and process crash. This vulnerability impacts web applications, queue workers, and other services that accept and process untrusted spreadsheet uploads using PhpSpreadsheet, enabling attackers to trigger denial of service conditions by simply providing a malicious file. Affected versions include all PhpSpreadsheet versions up to 1.30.5, and specific ranges within 2.x, 3.x, 4.x, and 5.x.

## Attack Chain

1. **Initial Access**: An attacker crafts a malicious `.gnumeric` file containing a small, highly compressed gzip payload designed to decompress into a significantly larger data size.
2. **Victim Interaction**: The attacker uploads this crafted `.gnumeric` file to a vulnerable application that uses the PhpSpreadsheet library for processing spreadsheet files (e.g., via a web form, API endpoint, or email attachment).
3. **File Read Initiation**: The vulnerable application calls PhpSpreadsheet's `PhpOffice\PhpSpreadsheet\Reader\Gnumeric::canRead()` method, or other loading functions, to determine the file type or extract information.
4. **Unbounded Decompression**: Inside `gzfileGetContents()`, the library detects the gzip magic bytes and proceeds to call `gzdecode()` on the entire compressed file contents.
5. **Memory Exhaustion**: During decompression, the small input file expands to an exceptionally large size (e.g., a 97KB file expands to 96MB), exceeding the PHP process's configured `memory_limit`.
6. **Application Crash**: The PHP interpreter encounters a "PHP Fatal error: Allowed memory size exhausted," leading to the immediate termination of the PHP process or worker handling the request.
7. **Denial of Service**: The application or service becomes unresponsive or crashes, effectively creating a denial of service condition for legitimate users or operations.

## Impact

Successful exploitation of CVE-2026-59932 leads directly to denial of service (DoS) for applications utilizing PhpSpreadsheet. A small, maliciously crafted `.gnumeric` file, for instance, a 97,811-byte file, can expand to approximately 96 MiB during processing. This rapid memory allocation exhausts the PHP process's memory limit (e.g., 64 MiB), causing a fatal error and crashing the application worker. Any service that accepts untrusted spreadsheet uploads, such as document converters, preview services, data import functionalities, or web applications handling user-uploaded files, is susceptible. This can result in service outages, reduced availability, and operational disruptions for affected organizations across various sectors.

## Recommendation

* Upgrade `composer/phpoffice/phpspreadsheet` to a patched version immediately to remediate CVE-2026-59932.
* Implement input validation and file size checks for all user-uploaded spreadsheet files to prevent excessively large files from being processed.
* Configure PHP's `memory_limit` to a reasonable, but not unbounded, value for processes handling file uploads, and monitor for sudden spikes in memory usage as a detection mechanism.
* Ensure that any custom file processing logic that handles gzipped data includes strict limits on the maximum allowed decompressed size.
