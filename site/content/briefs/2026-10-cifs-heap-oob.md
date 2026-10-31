---
brief_id: brief-2026-10-31-cifs-heap-oob
event_id: brief-2026-10-31-cifs-heap-oob
revision: 1
activity_at: "2026-10-31T19:41:48Z"
title: 'Linux Kernel cifs.ko: Heap Out-of-Bounds Write (CVE-2026-89633)'
slug: 2026-10-cifs-heap-oob
description: A heap out-of-bounds write vulnerability in the Linux kernel SMB1 client allows an attacker-controlled server to overwrite process credentials and escalate privileges to root.
date: "2026-10-31T19:41:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
tags:
  - kernel
  - privilege-escalation
  - smb1
  - cifs
  - cwe-787
products:
  - Linux Kernel (< 6.12.113)
affected_os:
  - Android 16
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The reference escalation chain turns the write into a real credential overwrite... making the process uid 0.
    confidence_band: high
cves:
  - id: CVE-2026-89633
    cvss: 9.8
    epss: 0.00491
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=BA42BDB4-C033-593B-9748-4E23020A615A
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=36d01415d881
  - https://sploitus.com/exploit?id=BA42BDB4-C033-593B-9748-4E23020A615A&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify and disable SMB1 (vers=1.0) mounts across the fleet.
      owner: IT Operations
      due: 24h
      evidence: The vulnerable code path exists only after the kernel cifs client has a session, i.e. after a cifs mount.
  hunt_leads:
    - lead: Monitor for CIFS/SMB mounts utilizing protocol version 1.0 (vers=1.0).
      technique_id: T1068
      data_needed:
        - Kernel mount logs (e.g., dmesg, /proc/mounts)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The mount is the privileged gate.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Linux kernel to 6.12.113 or higher.
      owner: IT Operations
      addresses: CVE-2026-89633
      evidence: Upstream fix 36d01415d881
---

CVE-2026-89633 is a heap out-of-bounds write vulnerability (CWE-787) in the Linux kernel `cifs.ko` module. The flaw exists in the `coalesce_t2()` function, which handles SMB1 `SMB_COM_TRANSACTION2_SECONDARY` responses. A malicious SMB1 server can send responses that trigger a write of 8-byte increments outside the bounds of the `server->bigbuf` buffer. An attacker can use this primitive to corrupt memory and perform a privilege escalation attack.

## Attack Chain
1. The victim client establishes an SMB1 mount to an attacker-controlled server or a machine susceptible to a Man-in-the-Middle (MitM) attack.
2. The client sends a TRANS2 request (e.g., `QUERY_FS_INFORMATION`).
3. The attacker-controlled server sends a primary response that triggers the large buffer path.
4. The attacker sends multiple `SMB_COM_TRANSACTION2_SECONDARY` responses.
5. The `coalesce_t2()` function copies secondary payload data to a destination calculated using an attacker-supplied `DataOffset` value.
6. The lack of bounds checking on `data_area_of_tgt` enables an out-of-bounds write relative to the response buffer.
7. The attacker uses the primitive to overwrite the `struct cred` of a target process on a page-aligned physical memory address.
8. Successful overwrite of the target's UID, GID, and SUIDs to zero results in root-level privilege escalation.

## Impact
Successful exploitation allows for arbitrary code execution and privilege escalation to the root user on systems mounting a malicious SMB1 share. The exploit requires an existing SMB1 session and is currently demonstrated as a build-specific research harness.

## Recommendation
- Patch the Linux kernel to version 6.12.113 or later, which incorporates the upstream fix `36d01415d881`.
- Disable support for the SMB1 protocol (`vers=1.0`) across all infrastructure to eliminate the attack vector.
- Audit mount configurations on Android and Linux endpoints to ensure that untrusted SMB shares are not automatically mounted.
- Restrict `CAP_SYS_ADMIN` privileges to prevent unauthorized creation of SMB mounts.
