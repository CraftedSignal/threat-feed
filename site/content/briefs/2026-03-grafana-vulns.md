---
title: Multiple Vulnerabilities in Grafana
slug: 2026-03-grafana-vulns
description: Multiple vulnerabilities in Grafana allow a remote attacker to conduct a denial-of-service attack, execute code, or disclose information.
date: "2026-03-30T11:04:00Z"
severities:
  - critical
tags:
  - grafana
  - vulnerability
  - dos
  - code-execution
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0899
rules:
  - title: Detect Grafana Path Traversal Attempts
    description: Detects potential path traversal attempts in Grafana web server logs by looking for '..' sequences in the URI query.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of Connections to Grafana Server
    description: Detects a potential denial-of-service attack by monitoring the number of connections to the Grafana server within a short period.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Multiple vulnerabilities have been identified in Grafana, a popular open-source data visualization and monitoring platform. These vulnerabilities can be exploited by remote attackers, either authenticated or anonymous, to achieve a range of malicious outcomes. Successful exploitation can lead to denial-of-service (DoS) conditions, unauthorized code execution, and sensitive information disclosure. Given Grafana's widespread use in monitoring critical infrastructure and business applications…
