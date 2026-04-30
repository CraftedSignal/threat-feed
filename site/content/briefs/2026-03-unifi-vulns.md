---
title: UniFi Network Application Vulnerabilities CVE-2026-22557 and CVE-2026-22558
slug: 2026-03-unifi-vulns
description: A combination of path traversal (CVE-2026-22557) and NoSQL injection (CVE-2026-22558) vulnerabilities in the UniFi Network Application allows attackers to access files, escalate privileges, and potentially compromise the entire system.
date: "2026-03-21T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - unifi
  - path-traversal
  - nosql-injection
  - cve-2026-22557
  - cve-2026-22558
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://ccb.belgium.be/advisories/warning-cve-2026-22557-cve-2026-22558-unifi-network-app-could-lead-full-system
  - https://community.ui.com/releases/Security-Advisory-Bulletin-062-062/c29719c0-405e-4d4a-8f26-e343e99f931b
  - https://www.cve.org/CVERecord?id=CVE-2026-22557
  - https://www.cve.org/CVERecord?id=CVE-2026-22558
rules:
  - title: Detect Path Traversal Attempts in UniFi Network Application Logs
    description: Detects potential path traversal attempts by monitoring logs for suspicious file access patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
  - title: Detect Potential NoSQL Injection in UniFi Network Application Logs
    description: Detects potential NoSQL injection attempts by monitoring logs for suspicious characters and keywords.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The UniFi Network Application, a central platform for managing network devices across enterprise and SMB environments, is affected by two critical vulnerabilities: CVE-2026-22557 (Path Traversal) and CVE-2026-22558 (Authenticated NoSQL Injection). These vulnerabilities impact Official Release versions 10.1.85 and earlier, Release Candidate versions 10.2.93 and earlier, and UniFi Express (UX) versions 9.0.114 and earlier. Exploitation of CVE-2026-22557 enables attackers to access and manipulate…
