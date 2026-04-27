---
title: Fortra GoAnywhere MFT SSH Key Brute-Force Vulnerability (CVE-2025-14362)
slug: 2026-04-goanywhere-bruteforce
description: Fortra's GoAnywhere MFT prior to 7.10.0 is vulnerable to brute-force attacks on SSH keys because the login limit is not enforced on the SFTP service when Web Users are configured to log in with an SSH Key.
date: "2026-04-22T12:00:00Z"
severities:
  - high
tags:
  - goanywhere
  - mft
  - bruteforce
  - ssh
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
cves:
  - id: CVE-2025-14362
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-14362
  - https://fortra.com/security/advisories/product-security/FI-2026-002
rules:
  - title: Detect Excessive Failed SSH Authentication Attempts on GoAnywhere MFT
    description: Detects a high number of failed SSH authentication attempts, potentially indicating a brute-force attack against GoAnywhere MFT.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - auth
      - linux
  - title: Detect Fortra GoAnywhere MFT service version via User-Agent
    description: Detects vulnerable Fortra GoAnywhere MFT service versions by checking the User-Agent string in HTTP requests. This is an informational rule that can help identify potentially vulnerable systems.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2025-14362 is a vulnerability affecting Fortra's GoAnywhere MFT servers prior to version 7.10.0. The vulnerability arises because the login limit is not enforced on the SFTP service when a Web User is configured to authenticate using an SSH key. This lack of enforcement allows attackers to conduct brute-force attacks against the SSH key, attempting to guess the key through repeated authentication attempts. Successful exploitation grants unauthorized access to the GoAnywhere MFT server…
