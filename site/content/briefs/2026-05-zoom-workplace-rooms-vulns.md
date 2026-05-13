---
title: Multiple Vulnerabilities in Zoom Workplace and Rooms
slug: 2026-05-zoom-workplace-rooms-vulns
description: A local attacker can exploit multiple vulnerabilities in Zoom Video Communications Workplace and Zoom Video Communications Rooms to disclose information or escalate privileges.
date: "2026-05-13T09:21:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - information-disclosure
  - zoom
vendors:
  - Zoom Video Communications
products:
  - Workplace
  - Rooms
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Local Account
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1507
rules:
  - title: Detect Suspicious Zoom Child Processes
    description: Detects suspicious child processes spawned by Zoom processes, potentially indicating privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Zoom File Access
    description: Detects Zoom processes accessing sensitive files outside of their normal operating scope, potentially indicating information disclosure.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Multiple vulnerabilities exist in Zoom Video Communications Workplace and Zoom Video Communications Rooms that a local attacker can exploit. The specific nature of these vulnerabilities is not detailed in the source, but the potential impact includes information disclosure and privilege escalation. This brief serves to highlight the existence of these vulnerabilities and to provide a basis for detection engineering teams to investigate and potentially implement mitigations based on their specific environment and available telemetry. The lack of specific CVEs or exploitation details necessitates a broad approach to detection and prevention.

## Attack Chain

Given the limited information, the following attack chain is a hypothetical scenario based on typical local privilege escalation and information disclosure techniques:

1.  Attacker gains initial local access to a system with Zoom Workplace or Rooms installed.
2.  Attacker identifies a vulnerable Zoom process running with elevated privileges.
3.  Attacker exploits a memory corruption vulnerability in the Zoom process to execute arbitrary code.
4.  Attacker uses the compromised Zoom process to read sensitive files or memory regions accessible to the Zoom process.
5.  Attacker leverages the compromised Zoom process to inject malicious code into other processes running with higher privileges.
6.  Attacker uses the injected code to create a new user with administrative privileges.
7.  Attacker logs in as the newly created user and gains full control of the system.

## Impact

Successful exploitation of these vulnerabilities by a local attacker could lead to sensitive information disclosure and complete system compromise through privilege escalation. The vulnerabilities affect Zoom Workplace and Zoom Rooms, potentially impacting organizations that rely on these products for communication and collaboration.

## Recommendation

*   Monitor process creations for unusual child processes spawned by Zoom processes to detect potential privilege escalation attempts (see Sigma rule "Detect Suspicious Zoom Child Processes").
*   Monitor file access patterns of Zoom processes for attempts to access sensitive files outside of their normal operating scope (see Sigma rule "Detect Suspicious Zoom File Access").
*   Implement least privilege principles to limit the privileges of Zoom processes and reduce the potential impact of successful exploitation.
