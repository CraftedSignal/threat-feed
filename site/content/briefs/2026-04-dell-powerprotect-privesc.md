---
title: Dell PowerProtect Data Domain Improper Certificate Validation Vulnerability
slug: 2026-04-dell-powerprotect-privesc
description: Dell PowerProtect Data Domain versions 7.7.1.0 through 8.5, 8.3.1.0 through 8.3.1.20, and 7.13.1.0 through 7.13.1.60, contain an improper certificate validation vulnerability in certificate-based login, potentially leading to privilege escalation.
date: "2026-04-17T10:16:04Z"
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - dell
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-23776
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23776
  - https://www.dell.com/support/kbdoc/en-us/000450699/dsa-2026-060-security-update-for-dell-powerprotect-data-domain-multiple-vulnerabilities
rules:
  - title: Detect Failed Certificate-Based Login Attempts
    description: Detects failed certificate-based login attempts which could indicate an exploitation attempt of CVE-2026-23776.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - authentication
      - dell_powerprotect_data_domain
  - title: Detect Certificate Login with Unusual User Agent
    description: Detects certificate-based logins with unusual user agents, potentially indicating unauthorized access after exploiting CVE-2026-23776.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - authentication
      - dell_powerprotect_data_domain
rules_count: 2
---

Dell PowerProtect Data Domain appliances running Data Domain Operating System (DD OS) are vulnerable to an improper certificate validation flaw (CVE-2026-23776). The vulnerability affects Feature Release versions 7.7.1.0 through 8.5, LTS2025 release version 8.3.1.0 through 8.3.1.20, and LTS2024 release versions 7.13.1.0 through 7.13.1.60. A low-privileged attacker with remote network access could exploit this vulnerability to elevate their privileges within the Data Domain system. Successful…
