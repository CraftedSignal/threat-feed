---
title: ksmbd Out-of-Bounds Write Vulnerability in QUERY_INFO (CVE-2026-31432)
slug: 2024-01-23-ksmbd-oob-write
description: CVE-2026-31432 is a critical out-of-bounds write vulnerability in ksmbd, specifically within the QUERY_INFO functionality when handling compound requests, potentially leading to code execution or denial of service.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ksmbd
  - smb
  - out-of-bounds write
  - cve-2026-31432
vendors:
  - Microsoft
cves:
  - id: CVE-2026-31432
    epss: 8e-05
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-31432
rules:
  - title: Detect Suspicious SMBv1 Negotiation
    description: Detects SMBv1 negotiation which may indicate older, vulnerable systems or attempts to downgrade connections.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect High Number of SMB Errors
    description: Detects a high number of SMB errors, potentially indicating exploitation attempts or misconfiguration issues.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-31432 is a critical vulnerability affecting the ksmbd server, a Linux kernel implementation of the SMB/CIFS protocol. The vulnerability is an out-of-bounds write that occurs when processing QUERY_INFO requests within compound SMB requests. An attacker could exploit this vulnerability by sending a specially crafted SMB request to a vulnerable ksmbd server. Successful exploitation could lead to arbitrary code execution in the context of the kernel or a denial-of-service condition. As a kernel-level vulnerability, exploitation can have severe consequences for system stability and security. The vulnerability highlights the ongoing challenges of ensuring the security of complex network protocols implemented within the kernel.

## Attack Chain

1. An attacker identifies a ksmbd server exposed on the network.
2. The attacker crafts a malicious SMB compound request containing a malformed QUERY_INFO request.
3. The attacker sends the crafted SMB request to the targeted ksmbd server.
4. The ksmbd server processes the request, triggering the out-of-bounds write in the QUERY_INFO handling routine.
5. The out-of-bounds write corrupts adjacent kernel memory.
6. Depending on the overwritten memory, the system may crash, leading to a denial-of-service condition.
7. Alternatively, an attacker may carefully craft the payload to overwrite specific kernel structures, potentially leading to arbitrary code execution.
8. Successful code execution allows the attacker to gain complete control over the affected system.

## Impact

Successful exploitation of CVE-2026-31432 could lead to a complete compromise of the affected system. An attacker could gain the ability to execute arbitrary code within the kernel, leading to data theft, system corruption, or the installation of rootkits. In less severe cases, exploitation could result in a denial-of-service condition, disrupting critical services. Given the potential for remote code execution, this vulnerability poses a significant risk to any system running a vulnerable version of ksmbd.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-31432 as soon as possible (reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-31432).
*   Deploy the Sigma rule `Detect Suspicious SMBv1 Negotiation` to identify potentially malicious SMB traffic patterns (reference: rule `Detect Suspicious SMBv1 Negotiation`).
*   Monitor network traffic for SMB requests originating from unexpected sources or containing unusual parameters (reference: Attack Chain Step 2).
*   Implement network segmentation to limit the potential impact of a successful exploit (reference: Attack Chain Step 1).
