---
title: Critical Vulnerabilities in NetScaler ADC and Gateway Allow Sensitive Data Exposure and Session Hijacking
slug: 2026-04-netscaler-vulns
description: Unauthenticated attackers can exploit CVE-2026-3055 (out-of-bounds read) to exfiltrate sensitive data from NetScaler ADC and Gateway, while CVE-2026-4368 (race condition) enables user session hijacking, necessitating immediate patching and enhanced monitoring.
date: "2026-04-01T08:44:01Z"
severities:
  - critical
exploited: true
tags:
  - netscaler
  - cve-2026-3055
  - cve-2026-4368
  - out-of-bounds read
  - race condition
  - memory corruption
  - session hijacking
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3055
    cvss: 9.8
    epss: 0.45194
  - id: CVE-2026-4368
    epss: 0.00017
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerabilities-netscaler-adc-netscaler-gateway-patch-immediately
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696300
rules:
  - title: Detect Netscaler CVE-2026-3055 GET Request
    description: Detects suspicious HTTP GET requests indicative of CVE-2026-3055 exploitation attempts targeting the SAML IDP in NetScaler ADC and Gateway.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Netscaler CVE-2026-4368 POST Request
    description: Detects suspicious HTTP POST requests indicative of CVE-2026-4368 exploitation attempts targeting the Gateway or AAA virtual server.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Citrix NetScaler ADC and Gateway are affected by two critical vulnerabilities, CVE-2026-3055 and CVE-2026-4368. CVE-2026-3055 is an out-of-bounds read vulnerability that allows an unauthenticated attacker to read arbitrary memory content. This could lead to the exfiltration of sensitive data like credentials and session tokens. CVE-2026-4368 is a race condition vulnerability that can lead to user session mix-up, potentially allowing one user to access another user's session. CISA has added…
