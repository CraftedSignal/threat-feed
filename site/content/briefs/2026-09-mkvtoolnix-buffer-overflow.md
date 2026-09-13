---
title: Heap Buffer Overflow in MKVToolNix avilib Library
slug: 2026-09-mkvtoolnix-buffer-overflow
description: MKVToolNix versions up to 101.0 are vulnerable to a heap buffer overflow in the avilib library, potentially allowing arbitrary code execution when processing crafted AVI files.
date: "2026-09-13T13:26:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mkvtoolnix:mkvtoolnix:*:*:*:*:*:*:*:*
vendors:
  - MKVToolNix
products:
  - MKVToolNix (<= 101.0)
cves:
  - id: CVE-2026-90783
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90783
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all instances of MKVToolNix to a version later than 101.0
      owner: IT Operations
      due: 7d
      evidence: CVE-2026-90783 fix identified in software update
  mitigation_plan:
    - priority: immediate
      action: Restrict execution of mkvmerge on untrusted AVI media
      owner: Security Operations
      addresses: CVE-2026-90783
      evidence: Vulnerability in avilib library's ODML superindex parser
---

MKVToolNix versions through 101.0 contain a critical heap buffer overflow vulnerability in the bundled avilib library. The flaw exists within the ODML superindex parser and is triggered by an integer wraparound during 32-bit arithmetic operations. An attacker can exploit this by distributing a specially crafted AVI file containing malicious entry counts. When a user parses this file using the mkvmerge utility, the application performs an undersized heap allocation. Subsequent operations then write data outside the bounds of this allocation, leading to a heap buffer overflow. This condition could allow an attacker to achieve arbitrary code execution or cause an application crash. Defenders should prioritize updating MKVToolNix to a version beyond 101.0 where the avilib library has been patched.

## Impact

Successful exploitation of this vulnerability could lead to arbitrary code execution on systems where users interact with maliciously crafted AVI files via the mkvmerge command-line utility or the MKVToolNix GUI. This affects all platforms running the vulnerable versions of the software, including Windows, Linux, and macOS.

## Recommendation

* Upgrade MKVToolNix to the latest version, which contains the fix for the avilib library and CVE-2026-90783.
* Audit file ingestion workflows that utilize mkvmerge for automated media processing to ensure they only process trusted files.
* Monitor for unexpected crashes of the mkvmerge process, which may indicate attempted exploitation of heap-based vulnerabilities.
