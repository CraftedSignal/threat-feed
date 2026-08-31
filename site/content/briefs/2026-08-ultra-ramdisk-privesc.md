---
title: Local Privilege Escalation in ieungSoft Ultra RAMDisk Pro URDSCSI.sys
slug: 2026-08-ultra-ramdisk-privesc
description: The URDSCSI.sys kernel driver in ieungSoft Ultra RAMDisk Pro 1.82 contains an improper privilege management vulnerability that allows local attackers to achieve privilege escalation.
date: "2026-08-31T17:58:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ieungsoft:ultra_ramdisk_pro:1.82:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - kernel-driver
  - windows
vendors:
  - ieungSoft
products:
  - Ultra RAMDisk Pro (1.82)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This manipulation causes improper privilege management. The attack needs to be launched locally.
    confidence_band: high
cves:
  - id: CVE-2026-82807
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82807
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory endpoints running Ultra RAMDisk Pro 1.82
      owner: IT Operations
      due: 24h
      evidence: Source confirms version 1.82 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Uninstall Ultra RAMDisk Pro 1.82
      owner: IT Operations
      addresses: CVE-2026-82807
      evidence: Vendor has not responded and no patch is available
---

A local privilege escalation vulnerability exists within the URDSCSI.sys kernel driver included in ieungSoft Ultra RAMDisk Pro version 1.82. The vulnerability stems from improper privilege management within the driver component, allowing an unprivileged local attacker to execute arbitrary code with kernel-level permissions. Publicly available exploit code exists, increasing the risk of exploitation for users of the affected software version. The vendor has not responded to disclosure attempts, and no security patches are currently available to remediate this flaw. Defenders should prioritize monitoring for the loading of this specific driver or suspicious interactions with the device object associated with URDSCSI.sys to identify potential exploitation attempts on host endpoints.

## Impact

Successful exploitation of CVE-2026-82807 allows a local user to gain unauthorized elevated privileges, potentially leading to full system compromise, data theft, or persistence within the environment. All organizations utilizing version 1.82 of Ultra RAMDisk Pro are vulnerable to local attack vectors.

## Recommendation

1. Inventory all endpoints running Ultra RAMDisk Pro version 1.82 and assess the business requirement for maintaining this software.
2. If the product is not critical, uninstall Ultra RAMDisk Pro version 1.82 until a vendor-supplied patch is available.
3. Restrict access to the system to prevent unauthorized local user sessions, as the attack requires local access to the target machine.
4. Implement endpoint monitoring to detect unusual interactions with kernel drivers or attempts to load unsigned/unauthorized modules.
