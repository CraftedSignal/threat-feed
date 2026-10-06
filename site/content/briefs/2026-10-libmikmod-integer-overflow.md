---
title: Integer Overflow Vulnerability in libmikmod DSM_Load
slug: 2026-10-libmikmod-integer-overflow
description: An integer overflow in libmikmod versions prior to 3.3.14 allows remote attackers to trigger heap buffer overflows via crafted DSM module files, potentially resulting in code execution.
date: "2026-10-06T14:55:56Z"
lastmod: "2026-10-06T14:56:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:libmikmod:libmikmod:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - buffer-overflow
vendors:
  - libmikmod
products:
  - libmikmod (< 3.3.14)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply an OKT module whose SLEN chunk wraps the 16-bit numtrk value, causing PBOD writes past allocated track pointers for crashes or code execution.
    confidence_band: high
cves:
  - id: CVE-2026-105837
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105837
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105839
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch all software packages using libmikmod to version 3.3.14.
      owner: IT Operations
      due: 48h
      evidence: libmikmod version 3.3.14 contains the fix for the integer overflow.
  mitigation_plan:
    - priority: immediate
      action: Upgrade libmikmod to 3.3.14.
      owner: IT Operations
      addresses: CVE-2026-105837
      evidence: Source NVD
updates:
  - at: "2026-10-06T14:56:03Z"
    level: L2
    summary: added coverage for libmikmod (< 3.3.14)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-105839
---

libmikmod, a portable sound library, contains an integer overflow vulnerability in the DSM_Load function located in load_dsm.c. This flaw affects all versions of the library prior to 3.3.14. The issue arises when the library parses a crafted DSM audio module file containing specific track count values. Specifically, the multiplication of the 'numchn' and 'numpat' parameters causes a 16-bit integer overflow. This overflow leads to an undersized allocation on the heap, which subsequently triggers a heap-based buffer overflow during memory write operations. An attacker who successfully delivers a malicious DSM file to an application utilizing the affected libmikmod version can cause a segmentation fault (application crash) or achieve arbitrary code execution within the context of the host process. This vulnerability is significant for any media player, game, or utility that processes untrusted music module files.

## Impact

Successful exploitation allows for the compromise of applications relying on libmikmod for audio decoding. Depending on the privileges of the target application, this could result in service disruption (denial of service via crash) or remote code execution. Given the prevalence of libmikmod in legacy gaming engines and multimedia software, the potential scope includes desktop users and server-side applications that perform media transcoding or file analysis.

## Recommendation

1. Upgrade all instances of libmikmod to version 3.3.14 or later to address the integer overflow in DSM_Load.
2. Implement memory safety tools such as AddressSanitizer (ASAN) during the build process of applications linking against libmikmod to detect heap corruption attempts in test environments.
3. Restrict the processing of untrusted DSM module files to sandboxed processes with minimal system privileges to contain potential code execution.
