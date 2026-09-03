---
title: Heap-based Buffer Overflow in zlib gz_vacate Function
slug: 2026-09-zlib-heap-overflow
description: zlib versions 1.3.1.2 through 1.3.2 are susceptible to a heap-based buffer overflow in the gz_vacate function, which can be triggered by specific non-blocking write operations to achieve memory corruption.
date: "2026-09-03T13:21:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zlib:zlib:1.3.1.2:*:*:*:*:*:*:*
  - cpe:2.3:a:zlib:zlib:1.3.2:*:*:*:*:*:*:*
vendors:
  - zlib
products:
  - zlib (1.3.1.2 - 1.3.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can trigger the overflow by calling gzprintf() or gzvprintf() after a write stall, causing an unchecked memmove() to write beyond the internal input buffer boundary.
    confidence_band: high
cves:
  - id: CVE-2026-85091
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85091
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  mitigation_plan:
    - priority: immediate
      action: Identify and patch zlib versions 1.3.1.2 through 1.3.2 across all production systems and software stacks.
      owner: IT Operations
      addresses: CVE-2026-85091
      evidence: Source document confirms these versions are vulnerable to a heap buffer overflow.
---

zlib versions 1.3.1.2 through 1.3.2 contain a heap-based buffer overflow vulnerability located within the gz_vacate() function. This vulnerability manifests when the library processes non-blocking gzwrite() operations while handling stale external buffer pointers. An attacker can force the execution of this vulnerable path by invoking gzprintf() or gzvprintf() specifically after a write stall has occurred. This sequence triggers an unchecked memmove() operation that writes data beyond the boundaries of the internal input buffer. Exploitation of this flaw can lead to significant memory corruption and potentially allow for arbitrary code execution within the context of the application utilizing the compromised zlib library. Given the ubiquity of zlib as a core compression component in numerous software packages, the impact of this vulnerability is widespread.

## Impact

Successful exploitation of CVE-2026-85091 allows for heap memory corruption, which can lead to application crashes or the execution of arbitrary code with the privileges of the affected process. This vulnerability affects any software relying on the specified versions of zlib for compression tasks, potentially exposing a wide range of enterprise applications and system-level utilities to remote or local code execution attacks.

## Recommendation

Update all software dependencies that include zlib versions 1.3.1.2 through 1.3.2 to the latest patched version of the library. Security teams should identify applications utilizing these specific zlib versions through software composition analysis (SCA) or vulnerability scanning tools. There are no known signature-based network detections for this flaw, as it relies on specific library-level function interactions. Focus remediation efforts on patching the underlying library code via software package managers (e.g., APT, YUM, NuGet, npm).
