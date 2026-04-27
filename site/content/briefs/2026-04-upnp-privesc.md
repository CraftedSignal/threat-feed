---
title: Windows UPnP Service Local Privilege Escalation via CVE-2026-32077
slug: 2026-04-upnp-privesc
description: CVE-2026-32077 is an untrusted pointer dereference vulnerability in the Windows Universal Plug and Play (UPnP) Device Host service that allows a locally authenticated attacker to escalate privileges.
date: "2026-04-14T18:35:17Z"
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - upnp
  - cve-2026-32077
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32077
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32077
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32077
rules:
  - title: Suspicious Process Creation from UPnP Host
    description: Detects suspicious process creation events originating from the UPnP Device Host service, potentially indicating exploitation of CVE-2026-32077.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: UPnP Host Spawning Unusual Network Connections
    description: Detects network connections initiated by the UPnP Device Host service to unusual ports or IPs, indicative of potential compromise following CVE-2026-32077 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32077 is a critical vulnerability affecting the Windows Universal Plug and Play (UPnP) Device Host service. This vulnerability stems from an untrusted pointer dereference within the UPnP service, potentially allowing an attacker with local access to escalate their privileges. Successful exploitation would grant the attacker elevated permissions, potentially leading to complete system compromise. Microsoft patched this vulnerability as part of their April 2026 security update. Given the…
