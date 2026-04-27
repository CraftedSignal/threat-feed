---
title: Provectus Kafka UI Code Injection Vulnerability (CVE-2026-5562)
slug: 2026-04-kafka-ui-code-injection
description: A code injection vulnerability exists in provectus kafka-ui up to version 0.7.2, specifically affecting the validateAccess function within the /api/smartfilters/testexecutions endpoint, allowing remote attackers to inject code.
date: "2026-04-05T11:16:56Z"
severities:
  - high
tags:
  - code-injection
  - kafka-ui
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-5562
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5562
  - https://vuldb.com/vuln/355332
rules:
  - title: Detect Kafka UI Code Injection Attempt
    description: Detects potential code injection attempts targeting the /api/smartfilters/testexecutions endpoint in Provectus Kafka UI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Kafka UI Code Injection Exploit (Process Creation)
    description: Detects process creation events that could indicate successful code injection via Kafka UI.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A code injection vulnerability, identified as CVE-2026-5562, affects provectus kafka-ui versions up to 0.7.2. The vulnerability resides within the `validateAccess` function of the `/api/smartfilters/testexecutions` endpoint, potentially allowing remote attackers to inject arbitrary code. This vulnerability allows for remote code execution, potentially leading to complete system compromise. The vendor was notified but did not respond. A public exploit is reportedly available, increasing the risk…
