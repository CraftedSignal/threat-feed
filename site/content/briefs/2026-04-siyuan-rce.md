---
title: SiYuan Knowledge Management System RCE via Malicious Website
slug: 2026-04-siyuan-rce
description: SiYuan versions prior to 3.6.2 are vulnerable to remote code execution (RCE) via a malicious website exploiting a permissive CORS policy to inject a JavaScript snippet, leading to arbitrary code execution within the application's Node.js context.
date: "2026-03-31T22:17:16Z"
severities:
  - critical
tags:
  - cve-2026-34449
  - rce
  - siyuan
  - cors
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34449
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34449
rules:
  - title: Detect Suspicious SiYuan API Access from Web Browser
    description: Detects network connections to the SiYuan API originating from web browsers, potentially indicating an exploitation attempt of CVE-2026-34449.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - network_connection
      - windows
  - title: Detect Processes Spawned from SiYuan Indicating RCE
    description: Detects the creation of unusual processes spawned directly from the SiYuan application, which could indicate successful remote code execution (RCE).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

SiYuan is a personal knowledge management system. Versions prior to 3.6.2 contain a critical vulnerability (CVE-2026-34449) that allows a malicious website to execute arbitrary code on any desktop running the application. This is achieved by exploiting an overly permissive Cross-Origin Resource Sharing (CORS) policy ("Access-Control-Allow-Origin: *" combined with "Access-Control-Allow-Private-Network: true"). An attacker can inject a JavaScript snippet into the application via its API. This…
