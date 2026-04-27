---
title: Red Hat Enterprise Linux Vulnerability Leads to Code Execution and Potential DoS
slug: 2026-03-rhel-code-execution
description: A remote, authenticated attacker can exploit a vulnerability in Red Hat Enterprise Linux (specifically 389-ds-base) to achieve arbitrary code execution and potentially cause a denial of service.
date: "2026-03-25T09:51:23Z"
severities:
  - critical
tags:
  - rhel
  - code-execution
  - denial-of-service
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0494
rules:
  - title: Detect Suspicious Processes Related to 389-ds-base
    description: Detects suspicious processes spawned by or related to the 389-ds-base service, which could indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Multiple Authentication Failures to 389 Directory Server
    description: Detects a high number of authentication failures to the 389 Directory Server from the same source IP, potentially indicating brute-force attempts to gain valid credentials.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1110.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A vulnerability exists in Red Hat Enterprise Linux, specifically within the 389-ds-base component. This flaw allows a remote, authenticated attacker to execute arbitrary code on the affected system. While the specific nature of the vulnerability isn't detailed, the authentication requirement suggests it likely involves a flaw in how the 389 Directory Server handles authenticated requests. Successful exploitation could lead to complete system compromise, allowing the attacker to install malware…
