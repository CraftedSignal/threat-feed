---
title: Denial of Service Vulnerability in NanaZip UFS Codec
slug: 2026-08-nanazip-dos
description: NanaZip 6.5 and earlier are vulnerable to a denial-of-service attack due to an unbounded memory allocation in the UFS codec handler triggered by a malicious fs_bsize value in a UFS image file.
date: "2026-08-18T14:30:04Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Jorge González Milla
tags:
  - dos
  - vulnerability
  - file-processing
vendors:
  - M2Team
products:
  - NanaZip (<= 6.5.1742.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: The attacker delivers the malicious UFS image to a target user via email, web download, or removable media.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker-controlled fs_bsize field in a crafted UFS image drives an unbounded allocation in the NanaZip.Codecs UFS handler before any bounds check.
    confidence_band: high
cves:
  - id: CVE-2026-55781
    epss: 0.00112
references:
  - https://www.exploit-db.com/exploits/52656
  - https://github.com/Pig-Tail/security-research/tree/master/CVE-2026-55781-NanaZip
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Deploy patch to version 6.5.1749.0 across all endpoints.
      owner: IT Operations
      due: 72h
      evidence: Vendor fix in 6.5.1749.0.
  mitigation_plan:
    - priority: immediate
      action: Block UFS file extensions via email and web proxies.
      owner: Security Operations
      addresses: CVE-2026-55781
      evidence: Exploit relies on specially crafted UFS image files.
---

NanaZip 6.5 and earlier versions contain a denial-of-service (DoS) vulnerability identified as CVE-2026-55781 within the NanaZip.Codecs UFS handler. The vulnerability exists because the application does not properly validate the fs_bsize field when parsing UFS image files. An attacker can craft a malicious UFS image file with an manipulated superblock fs_bsize value, forcing the UFS handler to perform unbounded memory allocation. This triggers excessive memory consumption, which can lead to application instability, unresponsiveness, or an immediate crash of the NanaZip process. This flaw was documented through a proof-of-concept generator that produces malformed UFS image files capable of exploiting this logic error. The issue was addressed in version 6.5.1749.0.

## Attack Chain

1. An attacker creates a malformed UFS image file (e.g., poc.img) incorporating a manipulated superblock.
2. The attacker modifies the fs_bsize field in the superblock to a large value (e.g., 1 GiB) within the crafted image.
3. The attacker sets the root inode (di_size) to an excessively large value, such as 1 TiB, to trigger buffer overrun logic.
4. The attacker delivers the malicious UFS image to a target user via email, web download, or removable media.
5. The target user attempts to open or extract the malicious UFS image using NanaZip.
6. The NanaZip.Codecs UFS handler processes the malformed image and reaches the vulnerable allocation routine.
7. The application performs an unbounded allocation of multiple GiBs of memory based on the tainted fs_bsize value.
8. The process exhausts available memory or triggers a memory management error, resulting in a denial-of-service (crash) of NanaZip.

## Impact

Successful exploitation results in the crash and denial-of-service of the NanaZip application. While the PoC demonstrates the logic flaw, this attack requires user interaction, typically involving the opening of a malicious archive. Organizations using NanaZip to process untrusted UFS image files are at risk of application-level service disruption.

## Recommendation

1. Update all instances of NanaZip to version 6.5.1749.0 or later to remediate CVE-2026-55781.
2. If immediate patching is not possible, implement strict file-type filtering on security gateways to block UFS image files from untrusted sources.
3. Use Endpoint Detection and Response (EDR) to monitor for NanaZip processes consuming excessive memory or experiencing recurring abnormal crashes.
