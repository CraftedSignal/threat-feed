---
title: AcyMailing WordPress Plugin Missing Authorization Vulnerability (CVE-2026-5200)
slug: 2026-05-acymailing-auth-bypass
description: The AcyMailing plugin for WordPress is vulnerable to a missing authorization issue (CVE-2026-5200), allowing authenticated attackers with subscriber-level access to modify privileged AcyMailing configuration, export subscriber secret keys, and potentially achieve administrator account takeover if the administrator's email address is known.
date: "2026-05-20T08:17:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - acymailing
  - wordpress
  - authorization-bypass
  - privilege-escalation
vendors:
  - WordPress
products:
  - AcyMailing – An Ultimate Newsletter Plugin and Marketing Automation Solution for WordPress plugin <= 10.8.2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
cves:
  - id: CVE-2026-5200
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5200
rules:
  - title: Detect CVE-2026-5200 Exploitation Attempt — Unauthorized AcyMailing Configuration Modification
    description: Detects attempts to modify AcyMailing configuration by unauthorized users exploiting CVE-2026-5200.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
  - title: Detect CVE-2026-5200 Exploitation Attempt — Unauthorized AcyMailing Subscriber Export
    description: Detects attempts to export subscriber secret keys via AcyMailing by unauthorized users exploiting CVE-2026-5200.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
rules_count: 2
---

The AcyMailing plugin for WordPress, up to version 10.8.2, suffers from a missing authorization vulnerability (CVE-2026-5200). This flaw enables authenticated attackers with minimal subscriber-level privileges to bypass authorization checks and perform actions normally reserved for administrators. This includes modifying sensitive plugin configurations and exporting subscriber secret keys. A successful exploit could lead to a complete compromise of the WordPress installation, especially if the attacker knows the email address of an administrator, facilitating an account takeover. Defenders should prioritize patching and monitoring activity related to this plugin.

## Attack Chain

1. An attacker registers an account on the WordPress site, obtaining subscriber-level access.
2. The attacker authenticates to the WordPress site using their subscriber credentials.
3. The attacker crafts a malicious HTTP request to modify AcyMailing configuration settings, bypassing authorization checks.
4. The attacker modifies settings related to email sending or subscriber management within AcyMailing.
5. The attacker crafts a separate HTTP request to export subscriber secret keys, again bypassing authorization checks.
6. The attacker analyzes the exported secret keys to gain further access or impersonate subscribers.
7. If the attacker knows the administrator's email address, they leverage the modified settings and exported data to attempt an administrator account takeover.
8. Successful account takeover grants the attacker full control over the WordPress site.

## Impact

Successful exploitation of this vulnerability allows attackers to modify AcyMailing settings, potentially leading to spam campaigns originating from the compromised WordPress site. More critically, an attacker can export subscriber secret keys, which could be used for malicious purposes. If the administrator's email is known, the attacker can leverage these exploits to achieve full administrator account takeover, leading to website defacement, data theft, or complete system compromise. The severity of this issue is reflected in its CVSS v3.1 base score of 8.8.

## Recommendation

*   Immediately update the AcyMailing plugin to the latest version, which includes a fix for CVE-2026-5200.
*   Deploy the Sigma rules provided to detect unauthorized modification attempts on AcyMailing configuration.
*   Monitor WordPress web server logs for suspicious HTTP requests targeting AcyMailing endpoints, particularly those attempting to modify configuration settings.
*   Review AcyMailing access logs for any unusual activity originating from subscriber-level accounts.
