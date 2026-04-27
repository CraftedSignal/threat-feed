---
title: OpenClaw Webchat Media Embedding Local-Root Containment Bypass
slug: 2026-04-openclaw-local-root-bypass
description: A vulnerability in OpenClaw versions 2026.4.7 to before 2026.4.15 allows a crafted tool-result media reference to cause the host to attempt local file reads or Windows UNC/network path access, potentially disclosing files or network credentials.
date: "2026-04-18T12:00:00Z"
severities:
  - medium
tags:
  - openclaw
  - local-file-inclusion
  - unc-path
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-mr34-9552-qr95
rules:
  - title: Detect Suspicious OpenClaw UNC Path Access
    description: Detects attempts by OpenClaw to access UNC paths, potentially indicating an exploitation of the local-root bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious OpenClaw File URL Access
    description: Detects attempts by OpenClaw to access file URLs, potentially indicating an exploitation of the local-root bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw versions 2026.4.7 through 2026.4.14 are vulnerable to a local-root containment bypass in the webchat media embedding feature. This flaw allows a malicious actor to craft a tool-result media reference with a local file path or UNC path that bypasses the intended `localRoots` containment policy. The vulnerability resides in the handling of media paths during webchat media block preparation on the host side. Successful exploitation could lead to the disclosure of allowed host files or the…
