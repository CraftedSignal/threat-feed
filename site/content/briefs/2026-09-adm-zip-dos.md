---
title: Denial of Service via Uncontrolled Memory Allocation in adm-zip
slug: 2026-09-adm-zip-dos
description: The adm-zip library is vulnerable to a denial of service (DoS) attack where a maliciously crafted ZIP archive forces excessive memory allocation by misrepresenting uncompressed file sizes.
date: "2026-09-18T19:50:24Z"
type: advisory
types:
  - advisory
severities:
  - low
cves:
  - id: CVE-2026-77301
    cvss: 7.5
---

The adm-zip library (version 0.6.1 and prior) contains a critical vulnerability, CVE-2026-77301, related to how it processes ZIP file metadata. When extracting or reading an entry, the library allocates an output buffer based on the 'uncompressed size' field declared in the central directory header before verifying the integrity of the data or matching it against the actual file size. 

An attacker can exploit this by crafting a small, legitimate-looking ZIP file (approximately 105 bytes) that declares a multi-gigabyte uncompressed size. This triggers an immediate, large-scale memory allocation when the `getData()` method is invoked. On memory-constrained environments such as containers, serverless functions, or small virtual machines, this behavior leads to immediate OOM-kills. Under higher load, even larger systems can be rendered unstable through resource exhaustion. This flaw poses a significant risk to any Node.js service that processes user-supplied ZIP files without external size validation.

## Impact

The vulnerability results in an effective Denial of Service (DoS) for any application utilizing the library to handle untrusted archives. A 105-byte file can commit over 1.8 GB of resident memory, causing process termination. The impact is highest in shared resource environments where a single malicious request can destabilize the host or trigger cascading failures in containerized workloads.

## Recommendation

1. Upgrade adm-zip to version 0.6.1 or later immediately.
2. Implement application-level validation for all uploaded files, specifically checking the declared size against reasonable constraints before invoking `adm-zip` processing.
