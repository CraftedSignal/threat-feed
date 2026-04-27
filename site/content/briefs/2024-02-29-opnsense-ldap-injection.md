---
title: OPNsense LDAP Injection Vulnerability (CVE-2026-34578)
slug: 2024-02-29-opnsense-ldap-injection
description: OPNsense versions prior to 26.1.6 are vulnerable to LDAP injection, allowing unauthenticated attackers to enumerate valid LDAP usernames and bypass group membership restrictions via the WebGUI login page.
date: "2026-04-09T15:16:10Z"
severities:
  - high
tags:
  - ldap-injection
  - vulnerability
  - opnsense
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34578
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34578
rules:
  - title: Detect OPNsense LDAP Injection Attempts
    description: Detects potential LDAP injection attempts in OPNsense WebGUI login requests by identifying LDAP metacharacters in the username field.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OPNsense LDAP Authentication Bypass Attempt
    description: Detects potential LDAP authentication bypass attempts in OPNsense by monitoring for specific LDAP metacharacters used to bypass group membership restrictions.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OPNsense, a FreeBSD-based firewall and routing platform, is susceptible to an LDAP injection vulnerability (CVE-2026-34578) in versions prior to 26.1.6. The vulnerability stems from the LDAP authentication connector's failure to sanitize the login username before incorporating it into an LDAP search filter. This oversight enables unauthenticated attackers to inject LDAP filter metacharacters through the username field of the WebGUI login page. This allows for enumeration of valid LDAP…
