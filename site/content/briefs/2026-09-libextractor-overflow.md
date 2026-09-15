---
title: Stack-Based Buffer Overflow in GNU libextractor
slug: 2026-09-libextractor-overflow
description: GNU libextractor versions prior to 1.15 contain a stack-based buffer overflow in the process_star_office function that can be triggered by malicious OLE2 stream data to cause application crashes.
date: "2026-09-15T01:38:15Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:gnu:libextractor:*:*:*:*:*:*:*:*
vendors:
  - GNU
products:
  - libextractor (< 1.15)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can craft malicious StarOffice documents that allocate up to 4 MB on the stack, causing stack overflow and crashing any application extracting metadata from the document.
    confidence_band: high
cves:
  - id: CVE-2026-91752
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91752
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade GNU libextractor to version 1.15 or later
      owner: IT Operations
      addresses: CVE-2026-91752
      evidence: GNU libextractor before 1.15 contains a stack-based buffer overflow vulnerability
---

GNU libextractor, a library used for extracting metadata from various file types, contains a stack-based buffer overflow vulnerability identified as CVE-2026-91752. The flaw resides within the process_star_office function, which handles StarOffice document formats. When the library parses an OLE2 stream within a crafted StarOffice document, it allocates memory on the stack based on attacker-supplied metadata headers. An attacker can craft a document requesting up to 4 MB of stack space, which exceeds typical stack limits and leads to a memory corruption event. This vulnerability primarily results in a denial-of-service, crashing any application or service that utilizes libextractor to process untrusted file uploads or metadata extraction tasks. Defenders should prioritize updating libextractor to version 1.15 or later to mitigate the risk of arbitrary code execution or service instability.

## Impact

The vulnerability poses a high risk to software ecosystems that utilize libextractor for automated file analysis, archival, or indexing. If successfully triggered, the overflow causes an immediate application crash, leading to service disruption. Systems that ingest user-provided documents are at the highest risk, as the exploitation vector requires nothing more than the library processing a malicious file.

## Recommendation

Update all instances of GNU libextractor to version 1.15 or later. Ensure that any software packages, dependencies, or local builds of the library are rebuilt and redeployed using the patched source code.
