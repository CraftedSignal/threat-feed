---
title: Apache ActiveMQ Vulnerabilities Allow RCE and XSS
slug: 2026-04-activemq-rce-xss
description: An authenticated remote attacker can exploit multiple vulnerabilities in Apache ActiveMQ to execute arbitrary program code or perform cross-site scripting attacks.
date: "2026-04-24T09:09:10Z"
severities:
  - critical
tags:
  - activemq
  - rce
  - xss
  - apache
vendors:
  - Apache
products:
  - ActiveMQ
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1258
rules:
  - title: Detect Suspicious ActiveMQ Console Access
    description: Detects access to the ActiveMQ web console from unusual locations or after hours.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect POST Requests to ActiveMQ API endpoints
    description: Detects suspicious POST requests to ActiveMQ API endpoints, potentially indicating exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities in Apache ActiveMQ allow a remote, authenticated attacker to execute arbitrary code or perform cross-site scripting (XSS) attacks. While specific CVEs and attack vectors are not detailed in this advisory, the presence of both RCE and XSS vulnerabilities suggests a high risk to organizations using affected versions of ActiveMQ. Exploitation requires authentication, implying that attackers may need to compromise credentials or exploit other vulnerabilities to gain initial…
