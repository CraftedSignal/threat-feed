---
title: CVE-2026-31704 ksmbd u16 DACL Size Overflow Vulnerability
slug: 2026-05-ksmbd-dacl-overflow
description: CVE-2026-31704 is a vulnerability in ksmbd related to the use of check_add_overflow() to prevent a u16 DACL size overflow, potentially leading to denial of service or privilege escalation.
date: "2026-05-19T07:12:53Z"
type: threat
types:
  - threat
severities:
  - medium
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
tags:
  - ksmbd
  - dacl
  - overflow
  - denial of service
  - privilege escalation
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-31704
    cvss: 5.5
    epss: 0.00013
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-31704
  - CVE-2026-31704
rules:
  - title: Detect Suspicious KSMBD DACL Size
    description: Detects CVE-2026-31704 exploitation — Monitors for SMB requests with unusually large DACL sizes, potentially indicating an attempt to trigger an integer overflow.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
  - title: Detect KSMBD Service Crash
    description: Detects a potential denial-of-service condition resulting from CVE-2026-31704 by monitoring for unexpected ksmbd service crashes.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - system
      - linux
rules_count: 2
---

CVE-2026-31704 is a security vulnerability affecting ksmbd, a Linux kernel implementation of the SMB/CIFS protocol. The vulnerability stems from an improper check when calculating the size of a Discretionary Access Control List (DACL). Specifically, the `check_add_overflow()` function is used to prevent a `u16` DACL size overflow. If this check is insufficient or improperly implemented, it could lead to an integer overflow, potentially resulting in a buffer overflow or other memory corruption issues. This could allow an attacker to cause a denial-of-service condition by crashing the ksmbd service, or potentially execute arbitrary code with elevated privileges on the affected system. The vulnerability was disclosed on May 19, 2026, as part of a Microsoft Security Response Center advisory.

## Attack Chain

1. An attacker sends a specially crafted SMB request to a server running a vulnerable version of ksmbd.
2. The SMB request contains a DACL with a size designed to trigger an integer overflow when processed.
3. The `check_add_overflow()` function fails to properly prevent the overflow during the DACL size calculation.
4. The incorrect DACL size is used to allocate memory for the DACL.
5. The subsequent write to the undersized memory buffer results in a buffer overflow.
6. The overflow corrupts adjacent memory regions, potentially including critical kernel data structures.
7. The corrupted data structures lead to a denial-of-service condition when the ksmbd service attempts to access them.
8. In a more sophisticated attack, the attacker may be able to control the overflow to overwrite specific kernel code or data, leading to arbitrary code execution.

## Impact

Successful exploitation of CVE-2026-31704 can lead to a denial-of-service condition, disrupting file sharing services provided by ksmbd. In a more severe scenario, an attacker could leverage the vulnerability to gain unauthorized access to the system, potentially escalating privileges to root. The specific impact depends on the configuration of the ksmbd service and the extent to which the attacker can control the memory overflow.

## Recommendation

- Apply the security update provided by Microsoft to patch CVE-2026-31704 to mitigate the vulnerability.
- Monitor systems running ksmbd for unusual SMB traffic patterns, especially requests with abnormally large DACLs.
- Deploy the Sigma rule "Detect Suspicious KSMBD DACL Size" to detect potentially malicious SMB requests attempting to exploit this vulnerability.
- Review and harden access control policies for SMB shares to minimize the attack surface.
