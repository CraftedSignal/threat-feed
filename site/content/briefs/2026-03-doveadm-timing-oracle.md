---
title: Doveadm Credentials Vulnerable to Timing Oracle Attack (CVE-2026-27856)
slug: 2026-03-doveadm-timing-oracle
description: Doveadm credentials are verified using direct comparison, making it susceptible to timing oracle attacks, allowing attackers to determine credentials and gain full access.
date: "2026-03-27T09:16:19Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - vulnerability
  - timing oracle
  - credential access
  - doveadm
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27856
  - https://documentation.open-xchange.com/dovecot/security/advisories/csaf/2026/oxdc-adv-2026-0001.json
rules:
  - title: Detect Suspicious Doveadm Authentication Attempts
    description: Detects suspicious authentication attempts to the Doveadm HTTP service, potentially indicating a timing oracle attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
  - title: Detect Doveadm HTTP Service Access from Unusual IPs
    description: Detects access to the Doveadm HTTP service from IP addresses not commonly seen accessing the service.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-27856 describes a vulnerability in Doveadm, a component often used in conjunction with mail servers such as Dovecot. The vulnerability stems from the direct comparison method used to verify credentials, making it susceptible to timing oracle attacks. This vulnerability was published on March 27, 2026. An attacker leveraging this flaw can potentially determine the configured credentials by observing the time it takes for the system to respond to different credential attempts. While no…
