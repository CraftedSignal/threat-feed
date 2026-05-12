---
title: UltraJSON Memory Leak in ujson.dump() on Write Failure (CVE-2026-44660)
slug: 2026-05-ultrajson-memory-leak
description: A memory leak vulnerability exists in UltraJSON's `ujson.dump()` function; when writing to a file-like object, if the write operation raises an exception, the serialized JSON string object is not properly de-referenced, leading to a memory leak (CVE-2026-44660).
date: "2026-05-12T22:28:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - memory leak
  - denial of service
  - python
  - ujson
  - CVE-2026-44660
vendors:
  - UltraJSON
products:
  - ujson (<= 5.12.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-c38f-wx89-p2xg
  - https://github.com/ultrajson/ultrajson/releases/tag/5.12.1
rules:
  - title: Detect UltraJSON ujson.dump Memory Leak
    description: Detects applications using ujson.dump() with file-like objects, potentially vulnerable to CVE-2026-44660-related memory leaks.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    data_sources:
      - process_creation
      - windows
  - title: Detect Python Process High Memory Usage
    description: Detects excessive memory usage by Python processes, which can be a sign of memory leak vulnerabilities such as CVE-2026-44660.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A memory leak vulnerability exists in UltraJSON's `ujson.dump()` function (CVE-2026-44660). When `ujson.dump()` writes to a file-like object and the write operation raises an exception, the serialized JSON string object is not de-referenced, leaking memory. This means that each failed write operation leaks the full size of the serialized payload. This issue affects applications that use `ujson.dump()` to serialize data to potentially unreliable file-like objects. Applications using `ujson.dumps()` or only JSON load/decode methods are not affected. The vulnerability was patched in UltraJSON version 5.12.1. An attacker can exploit this vulnerability to cause a denial-of-service by exhausting the available memory.

## Attack Chain

1. The attacker identifies an application that uses `ujson.dump()` to serialize data to a file-like object.
2. The attacker crafts a malicious input that, when processed by the application, triggers the `ujson.dump()` function.
3. The application calls `ujson_dumps_internal()` to serialize the data, allocating a Python string object.
4. The application attempts to write the serialized data to a file-like object using the file's `write()` method.
5. The attacker manipulates the file-like object to raise an exception during the `write()` operation.
6. The `write()` method fails, raising an exception that is caught by the application.
7. The `objToJSONFile()` function returns early due to the exception, without calling `Py_DECREF(string)` to de-reference the allocated string object.
8. The leaked memory accumulates with each failed write attempt, eventually exhausting the application's memory and causing a denial-of-service.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, where the application becomes unresponsive due to memory exhaustion. In a web server context, an attacker can repeatedly make requests and close the connection mid-response to trigger the memory leak. This can quickly consume all available memory, causing the server to crash or become unavailable to legitimate users. This vulnerability can impact any application that uses `ujson.dump()` and handles attacker-influenced file-like objects.

## Recommendation

*   Upgrade to UltraJSON version 5.12.1 or later to remediate the memory leak (see Remediation).
*   Replace `ujson.dump(obj, file)` with `file.write(ujson.dumps(obj))` as a workaround to avoid the memory leak (see Workarounds).
*   Enable process memory monitoring to detect processes with unusual memory growth patterns, which may indicate exploitation attempts.
*   Deploy the Sigma rule `Detect UltraJSON ujson.dump Memory Leak` to identify potential exploitation attempts by monitoring for write operations to file-like objects.
