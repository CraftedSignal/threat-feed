---
title: CODESYS Multiple Vulnerabilities Allow Arbitrary Code Execution and DoS
slug: 2026-03-codesys-vulns
description: Multiple vulnerabilities in CODESYS allow a remote attacker to execute arbitrary program code and conduct a denial-of-service attack.
date: "2026-03-25T09:46:08Z"
severities:
  - critical
tags:
  - codesys
  - vulnerability
  - arbitrary-code-execution
  - denial-of-service
  - ics
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0832
rules:
  - title: Suspicious Process Connecting to CODESYS Ports
    description: Detects unusual processes establishing network connections to common CODESYS ports.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Unexpected Process Creation Under CODESYS Directory
    description: Detects creation of new processes under the CODESYS installation directory which might indicate malicious activity
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified in CODESYS, a software platform widely used for industrial automation. These vulnerabilities, if exploited, could allow a remote attacker to execute arbitrary program code on affected systems and/or cause a denial-of-service (DoS) condition. Given the prevalence of CODESYS in critical infrastructure and manufacturing environments, these vulnerabilities pose a significant risk. Public details are limited, but the potential impact necessitates…
