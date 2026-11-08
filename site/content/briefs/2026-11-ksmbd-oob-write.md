---
brief_id: brief-2026-11-08-ksmbd-oob-write
event_id: brief-2026-11-08-ksmbd-oob-write
revision: 1
activity_at: "2026-11-08T11:39:23Z"
title: 'Linux Kernel ksmbd: Out-of-bounds write in SMB2 QUERY_INFO (CVE-2026-99273)'
slug: 2026-11-ksmbd-oob-write
description: An out-of-bounds heap write vulnerability in the Linux kernel ksmbd module allows an unauthenticated SMB client to corrupt kernel memory via malformed FileStreamInformation queries.
date: "2026-11-08T11:39:23Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
products:
  - ksmbd (Linux kernel <= 7.3.x)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Any SMB client that can open a file on a ksmbd share — including the guest/anonymous account — can make the in-kernel server write a UTF-16 NUL terminator two bytes past a 448-byte kmalloc response buffer.
    confidence_band: high
cves:
  - id: CVE-2026-99273
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=F5021413-F55B-5075-86F0-81957AE4BE59
  - https://github.com/torvalds/linux/commit/a025c4991a7d8
  - https://sploitus.com/exploit?id=F5021413-F55B-5075-86F0-81957AE4BE59&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Linux kernel via vendor package managers to address CVE-2026-99273
      owner: IT Operations
      due: 48h
      evidence: Commit a025c4991a7d8 provides the fix for the buffer size calculation.
  hunt_leads:
    - lead: Monitor for KASAN crash reports or kernel oops related to smb_strtoUTF16 within ksmbd
      technique_id: T1210
      data_needed:
        - dmesg
        - journalctl -k
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: KASAN reports appear right after QUERY_INFO on vulnerable systems.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to SMB service (TCP 445)
      owner: IT Operations
      addresses: CVE-2026-99273
      evidence: The vulnerability requires an SMB client to reach the ksmbd server.
---

A heap-based out-of-bounds write exists in the Linux kernel SMB server (ksmbd) implementation, specifically within the `get_file_stream_info()` function. The flaw occurs because the buffer size allocation logic for `SMB2 QUERY_INFO` responses fails to account for the UTF-16 NUL terminator appended by `smb_strtoUTF16()`. An attacker can cause a two-byte memory overwrite by supplying a stream name of a precise length that fills the 448-byte small buffer exactly, forcing the terminator to be written beyond the allocated boundary. This vulnerability affects Linux kernel versions up to 7.3.x using `CONFIG_SMB_SERVER`. The fix is available in mainline commit `a025c4991a7d8`.

## Attack Chain
1. Attacker establishes an SMB connection (anonymous/guest access is sufficient if enabled on the share).
2. Attacker issues a `SMB2 TREE_CONNECT` request to a `ksmbd` share.
3. Attacker uses `SMB2 CREATE` to open a file with specific `user.DosStream` xattr lengths.
4. Attacker issues a `SMB2 QUERY_INFO` request with the `FileStreamInformation` class.
5. The server invokes `get_file_stream_info()` to build the response.
6. The server performs an insufficient buffer check for the stream name conversion.
7. The `smb_strtoUTF16()` function writes a NUL terminator two bytes past the allocated heap buffer.

## Impact
The vulnerability allows an unauthenticated attacker to perform a fixed two-byte write of `0x0000` to kernel memory. While the corruption is restricted to a small, attacker-groomed buffer, it enables potential kernel memory corruption or stability issues on the target host.

## Recommendation
- Patch Linux kernel to at least commit `a025c4991a7d8` or apply the vendor-provided fix for distributions tracking stable 6.6 or 6.12 kernels.
- Disable guest/anonymous access to SMB shares if not strictly required to limit the attack surface.
- If immediate patching is not possible, restrict access to the SMB service (TCP 445) to trusted network segments.
