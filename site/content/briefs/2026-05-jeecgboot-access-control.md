---
title: JeecgBoot Improper Access Control Vulnerability (CVE-2026-9580)
slug: 2026-05-jeecgboot-access-control
description: JeecgBoot up to version 3.9.1 is vulnerable to improper access control in the LoginController.selectDepart function, allowing remote attackers to bypass intended restrictions.
date: "2026-05-26T21:18:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - access control
  - jeecgboot
vendors:
  - Jeecg
products:
  - JeecgBoot (<= 3.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-9580
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9580
  - https://github.com/jeecgboot/JeecgBoot/
  - https://github.com/jeecgboot/JeecgBoot/issues/9597
  - https://github.com/jeecgboot/JeecgBoot/issues/9597#issuecomment-4385501959
  - https://github.com/jeecgboot/JeecgBoot/releases/tag/v3.9.2
  - https://vuldb.com/submit/817892
  - https://vuldb.com/vuln/365636
  - https://vuldb.com/vuln/365636/cti
rules:
  - title: Detect CVE-2026-9580 Exploitation Attempt via selectDepart Access
    description: Detects CVE-2026-9580 exploitation — An attempt to access the /sys/selectDepart endpoint, potentially indicating unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

JeecgBoot, a low-code development platform, is susceptible to an improper access control vulnerability (CVE-2026-9580) affecting versions up to 3.9.1. Specifically, the `LoginController.selectDepart` function in the `/sys/selectDepart` file does not adequately restrict access, potentially allowing remote attackers to bypass intended authorization mechanisms. Public exploitation details are available, increasing the risk of exploitation. Upgrading to version 3.9.2 resolves this vulnerability. This vulnerability poses a threat to organizations using vulnerable versions of JeecgBoot, potentially leading to unauthorized data access or modification.

## Attack Chain

1.  The attacker identifies a JeecgBoot instance running a version prior to 3.9.2.
2.  The attacker sends a crafted HTTP request to the `/sys/selectDepart` endpoint.
3.  The request targets the `LoginController.selectDepart` function.
4.  Due to the improper access control, the attacker is able to bypass authentication checks.
5.  The attacker gains unauthorized access to departmental data.
6.  The attacker may modify or exfiltrate sensitive information.
7.  The attacker leverages the compromised access to escalate privileges within the application.

## Impact

Successful exploitation of CVE-2026-9580 can lead to unauthorized access to sensitive departmental data within JeecgBoot applications. This can result in data breaches, data modification, and privilege escalation, potentially impacting all organizations using JeecgBoot versions up to 3.9.1. The severity is compounded by the public availability of exploit details, increasing the likelihood of widespread exploitation.

## Recommendation

*   Upgrade JeecgBoot to version 3.9.2 or later to remediate CVE-2026-9580 (reference: CVE-2026-9580 and upgrade instructions in the overview).
*   Deploy the Sigma rule "Detect CVE-2026-9580 Exploitation Attempt via selectDepart Access" to identify potential exploitation attempts targeting the vulnerable endpoint (reference: the provided Sigma rule).
