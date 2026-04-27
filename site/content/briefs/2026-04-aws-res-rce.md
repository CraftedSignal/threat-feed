---
title: AWS Research and Engineering Studio (RES) RCE via FileBrowser API Vulnerability
slug: 2026-04-aws-res-rce
description: CVE-2026-5709 is a critical vulnerability in AWS Research and Engineering Studio (RES) versions 2024.10 through 2025.12.01, allowing remote authenticated attackers to execute arbitrary commands on the cluster-manager EC2 instance through the FileBrowser API.
date: "2026-04-06T22:16:25Z"
severities:
  - critical
tags:
  - cve-2026-5709
  - rce
  - aws
  - res
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5709
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5709
  - https://aws.amazon.com/security/security-bulletins/2026-014-aws/
  - https://github.com/aws/res/issues/150
  - https://github.com/aws/res/releases/tag/2026.03
rules:
  - title: Detect Suspicious FileBrowser API Requests
    description: Detects potentially malicious requests to the FileBrowser API in AWS Research and Engineering Studio (RES) by looking for common command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Potential File Uploads of Malicious Web Shells
    description: Detects potential attempts to upload web shells (PHP or HTML) through the FileBrowser API, which could be a sign of command execution exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5709 affects AWS Research and Engineering Studio (RES), a cloud-based platform for research and engineering workflows. The vulnerability resides in the FileBrowser API and is present in versions 2024.10 through 2025.12.01. An authenticated attacker can exploit this vulnerability by sending crafted input to the FileBrowser functionality, leading to arbitrary command execution on the underlying cluster-manager EC2 instance. This could allow attackers to gain complete control over the RES…
