---
title: 'CVE-2026-8449: Linux ksmbd Remote Memory Corruption Vulnerability'
slug: 2026-05-ksmbd-memory-corruption
description: A remote memory corruption vulnerability exists in Linux ksmbd that allows remote clients with directory creation permissions to trigger a heap out-of-bounds read and subsequent heap corruption by setting a crafted DACL with a malformed SID, potentially leading to kernel instability, denial of service, or privilege escalation.
date: "2026-05-12T22:18:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - defense-evasion
  - impact
  - memory corruption
vendors:
  - Linux
products:
  - ksmbd
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1210
    technique_name: Exploitation of Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1210
    technique_name: Exploitation of Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1210
    technique_name: Exploitation of Privilege Escalation
cves:
  - id: CVE-2026-8449
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8449
  - CVE-2026-8449
rules:
  - title: Detects CVE-2026-8449 Exploitation — Suspicious SMB2_SET_INFO Request with Malformed SID
    description: Detects CVE-2026-8449 exploitation — SMB2_SET_INFO request setting DACLs with malformed SIDs containing an inflated num_subauth field, indicating a potential heap out-of-bounds read attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - impact
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - network_connection
      - windows
  - title: Detects CVE-2026-8449 Exploitation - SMB Directory Creation followed by SET_INFO
    description: Detects CVE-2026-8449 exploitation — Monitors for directory creation followed by SMB2_SET_INFO requests setting DACLs, potentially indicating exploitation attempts against the ksmbd vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A remote memory corruption vulnerability, identified as CVE-2026-8449, exists within the Linux kernel's ksmbd module. This vulnerability resides in the ACL inheritance path, specifically in the handling of Discretionary Access Control Lists (DACLs). An attacker with directory creation permissions can exploit this flaw by crafting a malicious DACL containing a malformed Security Identifier (SID) with an inflated `num_subauth` field. This leads to a heap out-of-bounds read, ultimately resulting in heap corruption. Successful exploitation can cause kernel instability, denial of service, or privilege escalation, potentially allowing an attacker to execute arbitrary code within the kernel context.

## Attack Chain

1. Attacker authenticates to the target system with valid SMB credentials.
2. Attacker creates a new directory on the SMB share.
3. Attacker crafts a malicious DACL containing a malformed SID. The SID includes an inflated `num_subauth` field, which is designed to overflow the expected buffer size during processing.
4. The attacker uses the SMB2_SET_INFO request to set the crafted DACL on the newly created directory.
5. The ksmbd module processes the SMB2_SET_INFO request and attempts to apply the DACL to the directory.
6. Due to the malformed SID, the ACL inheritance path in ksmbd triggers a heap out-of-bounds read while attempting to process the `num_subauth` field.
7. This out-of-bounds read causes heap corruption, leading to kernel instability.
8. Further actions such as creating child entries within the directory exacerbate the corruption, potentially leading to denial of service or privilege escalation.

## Impact

Successful exploitation of CVE-2026-8449 can have severe consequences. The heap corruption caused by the malformed DACL can lead to kernel instability, resulting in a denial of service. In a more severe scenario, an attacker could potentially achieve privilege escalation and execute arbitrary code within the kernel context. This allows the attacker to gain complete control over the affected system. While the precise scope of the impact remains unclear, any system running a vulnerable version of ksmbd is at risk.

## Recommendation

*   Apply the patch or upgrade to a fixed version of the Linux kernel that addresses CVE-2026-8449.
*   Deploy the provided Sigma rule to detect attempts to exploit CVE-2026-8449 by monitoring for suspicious SMB2_SET_INFO requests setting DACLs with malformed SIDs.
*   Monitor SMB logs for abnormal directory creation activity followed by SMB2_SET_INFO requests, which could indicate exploitation attempts.
