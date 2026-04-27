---
title: Windows UPnP Device Host Untrusted Pointer Dereference Vulnerability (CVE-2026-27920)
slug: 2026-04-upnp-privesc
description: CVE-2026-27920 is a local privilege escalation vulnerability in the Windows Universal Plug and Play (UPnP) Device Host due to an untrusted pointer dereference.
date: "2026-04-14T18:17:01Z"
severities:
  - high
tags:
  - windows
  - privilege-escalation
  - cve
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27920
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27920
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27920
ioc_counts:
  email: 2
rules:
  - title: Suspicious Svchost Child Process Creation
    description: Detects suspicious child processes created by svchost.exe which may indicate privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: UPnP Device Host Service Executing Suspicious Binary
    description: Detects the Windows UPnP Device Host Service (svchost.exe -k LocalServiceNetworkRestricted) spawning cmd.exe, powershell.exe, or other suspicious binaries.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-27920 is a vulnerability affecting the Windows Universal Plug and Play (UPnP) Device Host. This vulnerability stems from an untrusted pointer dereference, which could allow an attacker with local access and authorization to escalate their privileges on the system. The vulnerability was published on April 14, 2026. An attacker who successfully exploits this vulnerability could gain higher-level access to the system potentially leading to complete system compromise. This privilege…
