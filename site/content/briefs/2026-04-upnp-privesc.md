---
title: Windows UPnP Device Host Use-After-Free Privilege Escalation (CVE-2026-27915)
slug: 2026-04-upnp-privesc
description: A use-after-free vulnerability (CVE-2026-27915) in Windows Universal Plug and Play (UPnP) Device Host allows a locally authorized attacker to elevate privileges.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-27915
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27915
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27915
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27915
ioc_counts:
  url: 1
rules:
  - title: UPnP Device Host Suspicious Child Process
    description: Detects suspicious child processes spawned by the UPnP Device Host service, potentially indicating exploitation of CVE-2026-27915.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: UPnP Device Host Suspicious Network Connection
    description: Detects suspicious network connections initiated by the UPnP Device Host service, potentially indicating exploitation of CVE-2026-27915.
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

CVE-2026-27915 is a use-after-free vulnerability affecting the Windows Universal Plug and Play (UPnP) Device Host service. This vulnerability allows an attacker who has already gained local access to a Windows system to elevate their privileges. The vulnerability resides within the UPnP service, a component designed to facilitate network device discovery and communication. Successful exploitation could allow a low-privileged user to execute arbitrary code with elevated permissions, potentially…
