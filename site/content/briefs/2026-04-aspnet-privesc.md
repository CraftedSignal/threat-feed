---
title: ASP.NET Core Improper Signature Verification Vulnerability (CVE-2026-40372)
slug: 2026-04-aspnet-privesc
description: CVE-2026-40372 is a critical vulnerability in ASP.NET Core stemming from improper cryptographic signature verification, potentially enabling unauthorized attackers to achieve network-based privilege escalation.
date: "2026-04-22T12:00:00Z"
severities:
  - critical
tags:
  - aspnet
  - privilege-escalation
  - cve-2026-40372
  - signature-bypass
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40372
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40372
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40372
rules:
  - title: Detect Suspicious ASP.NET Core Request
    description: Detects potential exploitation attempts of CVE-2026-40372 by monitoring for unusual patterns in ASP.NET Core requests indicative of signature bypass attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - windows
  - title: Detect ASP.NET Core Tampered Authentication Cookie
    description: Detects potential exploitation attempts by monitoring for modified or tampered ASP.NET authentication cookies.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-40372 describes a critical vulnerability affecting ASP.NET Core applications. This flaw arises from the improper verification of cryptographic signatures, creating an avenue for unauthorized attackers to elevate their privileges within a network. Successful exploitation of this vulnerability could grant attackers significant control over affected systems. According to the NVD, the CVE was published on April 21, 2026. Given the severity of privilege escalation and the potential for…
