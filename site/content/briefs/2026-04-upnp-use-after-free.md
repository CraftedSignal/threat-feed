---
title: CVE-2026-32156 Use-After-Free Vulnerability in Windows UPnP Device Host
slug: 2026-04-upnp-use-after-free
description: CVE-2026-32156 is a use-after-free vulnerability in the Windows Universal Plug and Play (UPnP) Device Host service that allows an unauthorized attacker to execute code locally.
date: "2026-04-14T18:39:36Z"
severities:
  - high
tags:
  - use-after-free
  - windows
  - upnp
  - code-execution
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2026-32156
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32156
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32156
ioc_counts:
  email: 1
rules:
  - title: Detect UPnP Service Launching Suspicious Processes
    description: Detects suspicious child processes spawned by the UPnP Device Host service (upnphost.dll), which could indicate exploitation of CVE-2026-32156.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect UPnP Service Connecting to External IP
    description: Detects suspicious network connections initiated by the UPnP Device Host service to external IPs, which could indicate exploitation of CVE-2026-32156.
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

CVE-2026-32156 is a use-after-free vulnerability affecting the Windows Universal Plug and Play (UPnP) Device Host service. This vulnerability allows a local, unauthorized attacker to execute arbitrary code. The vulnerability arises from improper memory management within the UPnP service when handling device discovery or control requests. Successful exploitation requires specific conditions to trigger the use-after-free condition. The vulnerability was reported to Microsoft and assigned a CVSS…
