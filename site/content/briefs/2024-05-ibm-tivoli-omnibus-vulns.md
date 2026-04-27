---
title: IBM Tivoli Netcool/OMNIbus Multiple Vulnerabilities
slug: 2024-05-ibm-tivoli-omnibus-vulns
description: An anonymous remote attacker can exploit multiple vulnerabilities in IBM Tivoli Netcool/OMNIbus to achieve arbitrary code execution, information disclosure, file manipulation, or denial of service.
date: "2026-03-25T10:21:05Z"
severities:
  - critical
tags:
  - ibm
  - tivoli
  - netcool
  - omnibus
  - vulnerability
  - code-execution
  - dos
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Standard System Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2022-1603
rules:
  - title: Detect Suspicious HTTP Error Codes
    description: Detects suspicious HTTP error codes that may indicate vulnerability scanning or exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect Webshell Activity
    description: Detects the execution of common webshell commands indicating potential webshell activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Multiple vulnerabilities exist in IBM Tivoli Netcool/OMNIbus that could be exploited by an anonymous remote attacker. The exact nature of these vulnerabilities is not specified, but successful exploitation could lead to a range of impacts, including arbitrary program code execution, sensitive information disclosure, unauthorized file manipulation, and denial of service. This broad range of potential impacts elevates the severity of this threat, as a successful attack could severely compromise…
