---
title: Cisco Smart Software Manager On-Prem RCE via Exposed API (CVE-2026-20160)
slug: 2024-02-cisco-ssm-rce
description: CVE-2026-20160 is a critical vulnerability in Cisco Smart Software Manager On-Prem (SSM On-Prem) that allows an unauthenticated, remote attacker to execute arbitrary commands on the underlying operating system with root privileges by sending a crafted request to an exposed API.
date: "2026-04-01T17:28:31Z"
severities:
  - critical
tags:
  - cve-2026-20160
  - cisco
  - ssm-on-prem
  - rce
  - webserver
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Software Vulnerability Exploitation
cves:
  - id: CVE-2026-20160
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20160
rules:
  - title: Detect Cisco SSM On-Prem API Exploitation Attempt
    description: Detects suspicious API requests potentially related to CVE-2026-20160 exploitation attempts on Cisco Smart Software Manager On-Prem.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Cisco SSM On-Prem Root Command Execution
    description: Detects command execution with root privileges originating from the Cisco Smart Software Manager On-Prem server, potentially indicating successful exploitation of CVE-2026-20160.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-20160 affects Cisco Smart Software Manager On-Prem (SSM On-Prem). The vulnerability allows an unauthenticated, remote attacker to execute arbitrary commands on the underlying operating system of an affected SSM On-Prem host. This is due to the unintentional exposure of an internal service. The vulnerability was reported in April 2026. Successful exploitation allows for command execution with root-level privileges, making it a critical risk for organizations using the affected Cisco SSM…
