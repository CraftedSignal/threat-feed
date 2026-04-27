---
title: IBM Total Storage Service Console (TSSC) / TS4500 IMC Unauthenticated Remote Command Execution
slug: 2026-04-ibm-tssc-rce
description: An unauthenticated user can execute arbitrary commands with normal user privileges on vulnerable IBM Total Storage Service Console (TSSC) / TS4500 IMC versions due to improper validation of user-supplied input, as identified by CVE-2026-5935.
date: "2026-04-23T00:16:46Z"
severities:
  - critical
tags:
  - cve-2026-5935
  - rce
  - command injection
vendors:
  - IBM
products:
  - Total Storage Service Console
  - TS4500 IMC
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5935
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5935
  - https://www.ibm.com/support/pages/node/7270127
rules:
  - title: Detect Exploitation Attempts CVE-2026-5935
    description: Detects potential exploitation attempts of CVE-2026-5935 based on suspicious HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect TSSC/IMC Command Injection via POST Request
    description: Detects command injection attempts targeting TSSC/IMC via POST requests with suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5935 describes a critical vulnerability affecting IBM Total Storage Service Console (TSSC) / TS4500 IMC software. Specifically, versions 9.2, 9.3, 9.4, 9.5, and 9.6 are susceptible to unauthenticated remote command execution. The vulnerability stems from insufficient validation of user-supplied input, allowing an attacker to inject and execute arbitrary commands on the system. Successful exploitation grants the attacker normal user privileges. This vulnerability poses a significant…
