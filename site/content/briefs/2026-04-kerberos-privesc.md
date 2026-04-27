---
title: Windows Kerberos Improper Authorization Privilege Escalation (CVE-2026-27912)
slug: 2026-04-kerberos-privesc
description: CVE-2026-27912 describes an improper authorization vulnerability in Windows Kerberos, enabling an attacker on an adjacent network with valid credentials to elevate privileges.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - kerberos
  - windows
  - cve-2026-27912
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
cves:
  - id: CVE-2026-27912
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27912
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27912
ioc_counts:
  email: 2
rules:
  - title: Detect Kerberos Ticket Request with Elevated Privileges
    description: Detects attempts to request Kerberos tickets with elevated privileges that may indicate exploitation of CVE-2026-27912
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1558.003
    data_sources:
      - security
      - windows
  - title: Detect Potential Kerberos Delegation Abuse
    description: Detects potential abuse of Kerberos delegation, which might be associated with privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1558.003
    data_sources:
      - security
      - windows
rules_count: 2
---

CVE-2026-27912 exposes an improper authorization flaw within the Windows Kerberos authentication protocol. This vulnerability allows an attacker who has already gained authorized access to an adjacent network to escalate their privileges. Successful exploitation of this vulnerability could lead to a complete compromise of the affected system. The vulnerability was reported to Microsoft and assigned CVE-2026-27912. Details regarding the specific Kerberos implementation flaws are still emerging…
