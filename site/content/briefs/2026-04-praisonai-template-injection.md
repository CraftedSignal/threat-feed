---
title: PraisonAI Template Injection Vulnerability (CVE-2026-40154)
slug: 2026-04-praisonai-template-injection
description: PraisonAI before version 4.5.128 is vulnerable to supply chain attacks due to treating remotely fetched template files as trusted executable code without proper verification, enabling exploitation via malicious templates.
date: "2026-04-09T22:16:36Z"
severities:
  - critical
tags:
  - cve-2026-40154
  - template-injection
  - supply-chain
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-40154
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40154
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-pv9q-275h-rh7x
ioc_counts:
  email: 2
rules:
  - title: Detect PraisonAI Template File Download
    description: Detects network connections to download template files by PraisonAI, which may indicate an exploitation attempt of CVE-2026-40154.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect PraisonAI Template File Download Linux
    description: Detects network connections to download template files by PraisonAI on linux systems.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to a critical vulnerability (CVE-2026-40154) affecting versions prior to 4.5.128. The application's design flaw involves treating remotely fetched template files as trusted executable code. This occurs without performing necessary security checks such as integrity verification, origin validation, or user confirmation. This lack of validation opens a significant attack vector, allowing for supply chain compromises. Attackers can inject…
