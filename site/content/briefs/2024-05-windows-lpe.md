---
title: Windows HTTP.sys Local Privilege Escalation Vulnerability (CVE-2026-21250)
slug: 2024-05-windows-lpe
description: A local privilege escalation vulnerability exists in Windows 11 24H2, Windows 11 25H2, and Windows Server 2022 23H2 due to improper handling of untrusted pointers in HTTP.sys via strcat truncation.
date: "2024-05-06T16:12:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - local-privilege-escalation
  - windows
  - cve-2026-21250
  - http.sys
vendors:
  - Microsoft
products:
  - Windows 11
  - Windows Server 2022
affected_os:
  - Windows 11 24H2
  - Windows 11 25H2
  - Windows Server 2022 23H2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Local Account
cves:
  - id: CVE-2026-21250
    cvss: 7.8
    epss: 0.00627
references:
  - https://www.exploit-db.com/exploits/52546
rules:
  - title: Detect Malicious HTTP Request to Trigger CVE-2026-21250
    description: Detects HTTP requests containing the X-Trigger-Ptr header, which is used in the CVE-2026-21250 exploit.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - windows
  - title: Detect HTTP Request with Malicious Pointer Payload
    description: Detects HTTP requests that have a malicious pointer payload within the X-Trigger-Ptr field.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - windows
rules_count: 2
---

A local privilege escalation vulnerability, CVE-2026-21250, affects Windows 11 24H2 (10.0.26100.7780), Windows 11 25H2 (10.0.26200.7780), and Windows Server 2022 23H2 (10.0.25398.2148). The vulnerability lies in the HTTP.sys driver and is triggered by sending a specially crafted HTTP request to a local HTTP service. The vulnerability arises because the `strcat()` function truncates binary malicious pointers, causing incomplete delivery of the untrusted pointer to the HTTP.sys driver, potentially leading to a Blue Screen of Death (BSOD) or random memory access errors. Successful exploitation allows a local attacker to gain elevated privileges on the system.

## Attack Chain

1. An attacker gains local access to a vulnerable Windows system.
2. The attacker starts the HTTP service (`net start http`).
3. The attacker crafts a malicious HTTP GET request containing the `X-Trigger-Ptr` header with a specially crafted payload.
4. The attacker sends the malicious HTTP request to the local HTTP service (127.0.0.1:80).
5. The `strcat()` function within the HTTP.sys driver truncates the malicious pointer due to the presence of a null byte (0x00).
6. The truncated, untrusted pointer is passed to the HTTP.sys driver.
7. The HTTP.sys driver attempts to dereference the truncated pointer.
8. This leads to a Blue Screen of Death (BSOD) or random memory access errors, potentially leading to privilege escalation.

## Impact

Successful exploitation of CVE-2026-21250 allows a local attacker to elevate their privileges on the targeted Windows system. While the provided exploit PoC focuses on triggering a BSOD, in a real-world scenario, the attacker could potentially leverage this vulnerability to gain SYSTEM privileges, leading to complete control over the compromised system.

## Recommendation

*   Monitor for suspicious HTTP requests with the `X-Trigger-Ptr` header using the Sigma rule provided below, specifically looking for truncated or malformed pointers (Sigma rule - "Detect Malicious HTTP Request to Trigger CVE-2026-21250").
*   Apply available patches from Microsoft to address the underlying vulnerability in HTTP.sys (CVE-2026-21250).
*   Implement network monitoring to detect unusual traffic patterns associated with the exploit, focusing on port 80 and HTTP GET requests (Sigma rule - "Detect HTTP Request with Malicious Pointer Payload").
*   Consider disabling the HTTP service if it is not required, reducing the attack surface.
*   Enable enhanced logging for the HTTP service to capture detailed information about incoming requests and potential exploitation attempts (Log source: webserver).
