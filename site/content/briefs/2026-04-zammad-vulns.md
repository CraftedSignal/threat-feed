---
title: Multiple Vulnerabilities in Zammad
slug: 2026-04-zammad-vulns
description: Multiple vulnerabilities in Zammad allow a remote attacker to execute arbitrary code, bypass security measures, disclose sensitive information, and perform cross-site scripting attacks.
date: "2026-04-09T08:09:17Z"
severities:
  - critical
tags:
  - zammad
  - vulnerability
  - code execution
  - xss
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1000
rules:
  - title: Detect Potential Zammad Code Execution via Web Request
    description: Detects potential attempts to exploit code execution vulnerabilities in Zammad via suspicious web requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Zammad XSS Attempt via URI
    description: Detects potential XSS attempts in Zammad via common JavaScript injection strings in the URI.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Zammad, a web-based open-source helpdesk and customer support system, is susceptible to multiple vulnerabilities. A remote, unauthenticated attacker may exploit these flaws to achieve arbitrary code execution, bypass security restrictions, conduct information disclosure, and launch cross-site scripting (XSS) attacks against users of the application. Successful exploitation of these vulnerabilities poses a significant risk to the confidentiality, integrity, and availability of the Zammad…
