---
title: 'CVE-2026-16118: Heap-Based Buffer Overflow in xdgmime'
slug: 2026-07-xdgmime-heap-buffer-overflow
description: A heap-based buffer overflow vulnerability exists in the `xdgmime` library, specifically within the `_xdg_mime_magic_parse_magic_line()` function, which can be triggered on little-endian systems when an application parses an attacker-controlled MIME magic file in a user-writable XDG data location, leading to an application crash or memory corruption.
date: "2026-07-17T20:27:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - buffer-overflow
  - linux
  - desktop-environment
products:
  - xdgmime
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A heap-based buffer overflow can be triggered ... resulting in an application crash or memory corruption.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: '...resulting in an application crash or memory corruption.'
    confidence_band: high
cves:
  - id: CVE-2026-16118
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16118
---

A significant vulnerability, CVE-2026-16118, has been identified in the `xdgmime` library, a component often used by applications for MIME type detection. This flaw manifests as a heap-based buffer overflow within the `_xdg_mime_magic_parse_magic_line()` function, located in the `xdgmimemagic.c` file. The vulnerability specifically affects little-endian systems and can be triggered when a vulnerable application attempts to parse a specially crafted MIME magic file. An attacker can place this malicious file in a user-writable XDG data location, such as `$XDG_DATA_HOME/mime/magic`. When an application (e.g., via `g_content_type_guess()`) subsequently parses this file, incorrect pointer arithmetic during a byte-swap operation causes a 2-byte out-of-bounds write. This can lead to application instability, including crashes, or more critical memory corruption, potentially enabling arbitrary code execution. This vulnerability poses a risk to users of applications that rely on `xdgmime` for MIME type identification, particularly if those applications process untrusted files.

## Attack Chain

1. An attacker crafts a malicious MIME magic file designed to exploit the heap-based buffer overflow in `xdgmime`.
2. The attacker gains the ability to place this crafted MIME magic file into a user-writable XDG data location on a target system (e.g., `$XDG_DATA_HOME/mime/magic`). This could involve exploiting another vulnerability or social engineering.
3. A legitimate application on the target, which relies on `xdgmime` for MIME type detection (e.g., a file manager or email client), attempts to parse the MIME magic files from known XDG data paths.
4. When the vulnerable application (running on a little-endian system) encounters the attacker-controlled MIME magic file, it initiates parsing using the `_xdg_mime_magic_parse_magic_line()` function.
5. During the parsing process, specifically when byte-swapping operations are performed, incorrect pointer arithmetic on the write side leads to a heap-based buffer overflow.
6. This results in an out-of-bounds write of 2 bytes, corrupting adjacent memory regions.
7. The memory corruption causes the application to crash, resulting in a denial of service, or, in more severe scenarios, could be leveraged by the attacker to achieve arbitrary code execution.

## Impact

The successful exploitation of CVE-2026-16118 primarily leads to application instability. Victims would experience application crashes, resulting in denial of service for the affected software. Depending on the memory layout and the attacker's capabilities, the memory corruption could be exploited further to achieve arbitrary code execution, granting the attacker control over the compromised application's process and potentially the system if the application runs with elevated privileges. No specific victim counts or targeted sectors are currently disclosed, but any system utilizing `xdgmime` in a vulnerable configuration is at risk.

## Recommendation

* Patch CVE-2026-16118 immediately by updating the `xdgmime` library to a version that addresses this heap-based buffer overflow. Consult your distribution or software vendor for official updates.
* Implement file integrity monitoring on critical XDG data locations, such as `$XDG_DATA_HOME/mime/magic`, to detect unauthorized modifications.
* Review applications that parse MIME magic files to understand their dependency on `xdgmime` and potential exposure to CVE-2026-16118.
