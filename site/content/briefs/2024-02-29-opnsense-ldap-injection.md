---
title: OPNsense LDAP Injection Vulnerability (CVE-2026-34578)
slug: 2024-02-29-opnsense-ldap-injection
description: OPNsense versions prior to 26.1.6 are vulnerable to LDAP injection, allowing unauthenticated attackers to enumerate valid LDAP usernames and bypass group membership restrictions via the WebGUI login page.
date: "2026-04-09T15:16:10Z"
severities:
  - high
type: advisory
types:
  - advisory
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

OPNsense, a FreeBSD-based firewall and routing platform, is susceptible to an LDAP injection vulnerability (CVE-2026-34578) in versions prior to 26.1.6. The vulnerability stems from the LDAP authentication connector's failure to sanitize the login username before incorporating it into an LDAP search filter. This oversight enables unauthenticated attackers to inject LDAP filter metacharacters through the username field of the WebGUI login page. This allows for enumeration of valid LDAP usernames. Furthermore, if the LDAP server configuration employs an Extended Query to limit login access to specific group members, the same injection technique can circumvent this restriction, enabling authentication as any LDAP user with a known password, irrespective of their group affiliation. The vulnerability is resolved in OPNsense version 26.1.6.

## Attack Chain

1. An unauthenticated attacker accesses the OPNsense WebGUI login page.
2. The attacker crafts a malicious username containing LDAP filter metacharacters.
3. The attacker submits the crafted username along with a password (if attempting to bypass group restrictions) through the WebGUI login form.
4. The OPNsense LDAP authentication connector receives the username.
5. The connector incorporates the unsanitized username directly into an LDAP search filter.
6. The LDAP server executes the injected LDAP query.
7. The LDAP server returns results based on the injected filter, potentially revealing valid usernames or authenticating the attacker as an unintended user.
8. If successful in bypassing group restrictions, the attacker gains unauthorized access to the OPNsense system with the privileges of the targeted LDAP user.

## Impact

Successful exploitation of this vulnerability can allow attackers to enumerate valid usernames within the LDAP directory, potentially aiding in further attacks such as credential stuffing. More critically, it allows attackers to bypass group membership restrictions, granting them unauthorized access to the OPNsense system and the network it protects. This could lead to data breaches, system compromise, and disruption of services. The specific impact depends on the privileges associated with the compromised LDAP user.

## Recommendation

*   Upgrade OPNsense to version 26.1.6 or later to patch CVE-2026-34578 immediately.
*   Deploy the Sigma rule `Detect OPNsense LDAP Injection Attempts` to identify exploitation attempts based on specific LDAP metacharacters in HTTP requests.
*   Review OPNsense webserver logs for unusual patterns in the username field of login requests.
*   Implement web application firewall (WAF) rules to filter out LDAP metacharacters in the username field of login requests to mitigate the risk of exploitation.
