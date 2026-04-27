---
title: Anviz CrossChex Standard TDS7 PreLogin Encryption Vulnerability
slug: 2026-04-anviz-crosschex-vuln
description: Anviz CrossChex Standard is vulnerable to unauthorized database access due to the manipulation of TDS7 PreLogin, which disables encryption, leading to plaintext transmission of database credentials.
date: "2026-04-18T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-32650
  - credential-access
  - database
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-32650
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32650
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-106-03.json
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-106-03
ioc_counts:
  email: 1
rules:
  - title: Detect Unencrypted TDS7 PreLogin Connection
    description: Detects network connections to the TDS7 PreLogin port without encryption, indicating potential exploitation of CVE-2026-32650.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - network_connection
      - windows
  - title: Detect Potential Database Access from Unexpected Process
    description: Detects processes other than the legitimate Anviz CrossChex application accessing the database.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Anviz CrossChex Standard is susceptible to a critical vulnerability (CVE-2026-32650) where an attacker can manipulate the TDS7 PreLogin process. By exploiting this flaw, an attacker can disable encryption mechanisms, causing sensitive database credentials to be transmitted in plaintext. This exposure enables unauthorized access to the underlying database, potentially leading to data breaches, modification of records, or other malicious activities. The vulnerability was disclosed in April 2026…
