---
title: Heap Buffer Over-Read Vulnerability in libexpat
slug: 2026-10-libexpat-heap-over-read
description: An unvalidated buffer length parameter in the libexpat XML_ParseBuffer function allows remote attackers to trigger a heap buffer over-read, potentially leaking sensitive memory for ASLR bypass.
date: "2026-10-07T17:03:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:libexpat:expat:*:*:*:*:*:*:*:*
vendors:
  - libexpat
products:
  - libexpat (< commit 13c5f63)
cves:
  - id: CVE-2026-77214
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77214
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  mitigation_plan:
    - priority: immediate
      action: Upgrade libexpat to commit 13c5f63 or higher
      owner: Development
      addresses: CVE-2026-77214
      evidence: NVD vulnerability report
---

libexpat versions prior to commit 13c5f63 contain a critical heap buffer over-read vulnerability located in the xmlparse.c file. The vulnerability stems from the XML_ParseBuffer function, which increments the parser->m_bufferEnd pointer using a caller-supplied length without performing bounds checking against the allocated heap size. By repeatedly invoking XML_ParseBuffer, an attacker can push the buffer end pointer past the allocated memory boundary. 

To trigger this condition, the application must already have an active parse buffer, which is typically established via a call to XML_GetBuffer or internally during a prior XML_Parse operation. If exploited, the vulnerability leads to the disclosure of adjacent heap data. This information leak can be used to recover heap pointers, libc function addresses, and code pointers, which provides the necessary primitives to defeat Address Space Layout Randomization (ASLR) and enables more complex exploitation. Given libexpat's wide usage in cross-platform software, this vulnerability poses a significant risk to applications that process untrusted XML data.

## Impact

Successful exploitation allows for the disclosure of sensitive heap memory contents. By leaking function pointers and internal memory addresses, an attacker can neutralize ASLR protections on a target system. This vulnerability affects any software utilizing libexpat to parse external or untrusted XML input, regardless of the operating system, potentially leading to remote code execution when combined with other memory corruption vulnerabilities.

## Recommendation

1. Patch all instances of libexpat to a version incorporating the fix in commit 13c5f63 or later.
2. Implement strict input validation on all XML sources processed by libexpat-dependent applications to prevent the submission of maliciously crafted XML payloads.
3. Where possible, utilize hardened memory allocators that provide additional protection against heap buffer overflows and over-reads.
