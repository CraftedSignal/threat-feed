---
title: Heap Buffer Overflow in stb_vorbis
slug: 2026-09-stb-vorbis-heap-overflow
description: A heap-based buffer overflow in the stb_vorbis library allows for arbitrary code execution via a maliciously crafted Ogg Vorbis audio file.
date: "2026-09-12T01:16:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nothings:stb_vorbis:*:*:*:*:*:*:*:*
vendors:
  - nothings
products:
  - stb_vorbis (<= 1.22)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can craft a malicious Ogg Vorbis file with large entries and dimensions values to trigger out-of-bounds writes, causing process crashes or heap corruption.
    confidence_band: high
cves:
  - id: CVE-2026-89266
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89266
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Identify and patch applications embedding vulnerable stb_vorbis <= 1.22
      owner: IT Operations
      addresses: CVE-2026-89266
      evidence: stb_vorbis through 1.22 contains a heap buffer overflow
---

The stb_vorbis library, up to and including version 1.22, contains a critical heap-based buffer overflow vulnerability within the start_decoder function. The flaw occurs due to integer truncation when calculating the allocation size for codebook multiplicands; the library incorrectly casts a size_t value to an int, leading to an undersized allocation. An attacker can exploit this vulnerability by providing a specially crafted Ogg Vorbis file containing abnormally large entries and dimensions. Successful exploitation of this vulnerability results in out-of-bounds writes, which can be leveraged to corrupt the heap or achieve arbitrary code execution within the context of the application consuming the audio file. Because stb_vorbis is a common header-only library embedded within various cross-platform applications and game engines, the impact scope is broad, affecting any system parsing untrusted Ogg Vorbis content.

## Impact

Successful exploitation allows for memory corruption and potential arbitrary code execution. This impacts any software that utilizes the stb_vorbis library to process audio files, including media players, game engines, and transcoding tools on Windows, Linux, and macOS. If the vulnerable application runs with elevated privileges or processes user-provided content from the internet, the risk of exploitation is significantly increased.

## Recommendation

- Identify all software components within your environment that bundle the stb_vorbis library.
- Update any identified software to a version that utilizes a patched release of stb_vorbis (beyond 1.22).
- Implement memory safety monitoring for media processing applications to detect heap-related crashes.
- Disable support for Ogg Vorbis files in applications where it is not required for core functionality to reduce the attack surface.
