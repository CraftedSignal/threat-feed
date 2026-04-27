---
title: Apache ActiveMQ Multiple Vulnerabilities Allow Remote Code Execution
slug: 2026-04-activemq-vulns
description: An authenticated remote attacker can exploit multiple vulnerabilities in Apache ActiveMQ to manipulate files or execute arbitrary code.
date: "2026-04-16T05:29:10Z"
severities:
  - critical
tags:
  - apache-activemq
  - vulnerability
  - rce
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0991
rules:
  - title: Detect Suspicious ActiveMQ Process Execution
    description: Detects unusual process execution originating from the ActiveMQ installation directory, potentially indicating exploitation or malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect ActiveMQ Web Console Authentication Brute Force
    description: Detects a high number of failed authentication attempts against the ActiveMQ web console, potentially indicating a brute-force attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities in Apache ActiveMQ, a popular open-source message broker, can be exploited by an authenticated remote attacker to achieve arbitrary code execution or manipulate files. This threat affects ActiveMQ brokers, clients, and web consoles. Given ActiveMQ's widespread use in enterprise environments for inter-application communication, successful exploitation could lead to significant data breaches, service disruptions, and lateral movement within the affected networks. The…
