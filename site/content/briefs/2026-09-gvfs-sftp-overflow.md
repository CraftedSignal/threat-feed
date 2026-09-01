---
title: Heap-Based Buffer Overflow in gvfs SFTP Backend
slug: 2026-09-gvfs-sftp-overflow
description: The gvfsd-sftp process contains a heap-based buffer overflow vulnerability that allows a malicious SFTP server to corrupt memory via crafted file read responses.
date: "2026-09-01T17:07:26Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:gnome:gvfs:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
  - linux
vendors:
  - GNOME
products:
  - gvfs
cves:
  - id: CVE-2026-84268
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84268
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade gvfs package to the latest version containing the patch for CVE-2026-84268
      owner: IT Operations
      addresses: CVE-2026-84268
      evidence: NVD vulnerability report confirms CVE-2026-84268
---

A heap-based buffer overflow vulnerability (CVE-2026-84268) exists in the SFTP backend of the GNOME Virtual File System (gvfs). The flaw resides in the read_reply() function, which fails to properly validate the length of data returned by an SFTP server against the allocated buffer size. When a user mounts an SFTP share and attempts to read a file, a malicious SFTP server can provide a length value that exceeds the client-requested size. This causes the gvfsd-sftp process to write data beyond the intended buffer boundaries, corrupting adjacent heap memory. This exploitation can lead to a denial-of-service condition if the process crashes due to detected heap corruption, or potentially allow for arbitrary code execution in the context of the gvfsd-sftp process. Defenders should prioritize patching gvfs on all Linux systems using the GNOME desktop environment.

## Impact

Successful exploitation of CVE-2026-84268 can result in local denial-of-service or remote code execution via a malicious server connection. This affects Linux distributions utilizing the GNOME stack, particularly impacting workstations and servers that frequently mount external SFTP shares. The severity is rated at 8.8 (CVSS v3.1), reflecting the potential for significant memory corruption and system instability.

## Recommendation

- Apply security patches for the gvfs package provided by your Linux distribution maintainer to address CVE-2026-84268.
- Audit system configurations to ensure users are not required to mount untrusted SFTP shares via gvfs until patches are applied.
- Prioritize updating all GNOME-based desktop environments on internet-facing or high-risk endpoints.
