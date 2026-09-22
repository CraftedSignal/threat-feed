---
title: Denial of Service via Uncontrolled Memory Allocation in psd-tools
slug: 2026-09-psd-tools-memory-dos
description: An improper input validation vulnerability in psd-tools (CVE-2026-59991) allows attackers to trigger massive, unvalidated memory allocations using maliciously crafted PSD files, leading to OOM-kill of the host service.
date: "2026-09-22T19:53:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:psd-tools_project:psd-tools:*:*:*:*:*:python:*:*
products:
  - psd-tools (< 1.17.4)
references:
  - https://github.com/advisories/GHSA-8q6g-vjhf-jp8m
iocs:
  - type: hash_sha256
    value: 7d8ebf03a54393cb0359ecf4b676d1b08c9a8c6afdd06671ef406d6893cce826
ioc_counts:
  hash_sha256: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade psd-tools to 1.17.4 or later
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerable version is < 1.17.4
  hunt_leads:
    - lead: Search for file hash 7d8ebf03a54393cb0359ecf4b676d1b08c9a8c6afdd06671ef406d6893cce826 in application storage
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Provided PoC file hash in the advisory
  mitigation_plan:
    - priority: immediate
      action: Enforce file size limits and dimension validation before calling PSDImage.composite()
      owner: Application Security
      addresses: CVE-2026-59991
      evidence: Root cause is lack of dimension validation
---

The Python library psd-tools, version 1.17.2 and earlier, is vulnerable to an uncontrolled memory allocation flaw (CVE-2026-59991). When processing a PSD file, the `PSDImage.composite()` and `PSDImage.numpy()` functions allocate an output image buffer based on dimensions declared within the PSD file's header before validating these dimensions against the actual file size or reasonable constraints.

An attacker can provide a small, maliciously crafted PSD file, as small as 49 bytes, that declares extremely large width, height, or layer dimensions. This forces the application to commit gigabytes of memory for the buffer, far exceeding the size of the input file. Because the library fails to throw an exception upon detecting mismatched geometry and instead returns a black image, the caller is unable to detect the malicious nature of the file. This vulnerability is critical for web services or backend applications that process untrusted user-supplied images, as it allows for an unrecoverable out-of-memory (OOM) kill of the host process with minimal bandwidth usage.

## Impact

Successful exploitation results in a denial-of-service condition due to host system resource exhaustion. An attacker can crash web servers or background job workers processing image uploads by committing up to 32 GB of memory from a single, sub-100-byte payload. This poses a significant threat to any service or application that allows users to upload PSD files for processing, indexing, or format conversion.

## Recommendation

Prioritized actions for engineering and security teams:

- Upgrade psd-tools to version 1.17.4 or later immediately to include validation logic that mitigates memory over-allocation.
- Implement a maximum file size limit and a maximum pixel dimension check for all user-supplied image uploads at the application layer before passing the data to the psd-tools library.
- Monitor logs for repeated service restarts or process crashes involving `psd-tools` to identify potential exploitation attempts.
- Use the provided SHA-256 hash (7d8ebf03a54393cb0359ecf4b676d1b08c9a8c6afdd06671ef406d6893cce826) to scan existing file storage for known malicious PoC payloads.
