---
title: Multiple Vulnerabilities in Apache Tomcat Allow for Remote Code Execution and Data Manipulation
slug: 2024-06-apache-tomcat-vulns
description: Multiple vulnerabilities in Apache Tomcat can be exploited by a remote, authenticated or anonymous attacker to execute arbitrary code, bypass security measures, manipulate data, and cause a denial of service.
date: "2026-03-25T10:22:01Z"
severities:
  - critical
tags:
  - apache-tomcat
  - vulnerability
  - remote-code-execution
  - data-manipulation
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2420
rules:
  - title: Detect Suspicious Tomcat Request
    description: Detects suspicious HTTP requests potentially targeting Apache Tomcat vulnerabilities
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    data_sources:
      - webserver
      - linux
  - title: Tomcat Access Log Anomalies
    description: Detects anomalies in Apache Tomcat access logs that might indicate exploitation attempts
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A remote attacker, either authenticated or anonymous, can exploit multiple vulnerabilities within Apache Tomcat. Successful exploitation can lead to arbitrary code execution, bypassing security measures, manipulating sensitive data, and triggering a denial-of-service condition, severely impacting availability and confidentiality. This broad range of potential impacts makes timely patching and robust detection critical for organizations utilizing Apache Tomcat. The absence of specific CVEs in…
