---
title: Maddy Mail Server LDAP Filter Injection Vulnerability
slug: 2024-01-maddy-ldap-injection
description: Maddy Mail Server is vulnerable to LDAP injection via unsanitized username in the `auth.ldap` module, enabling identity spoofing, LDAP directory enumeration, and attribute value extraction by injecting arbitrary LDAP filter expressions through the username field in SMTP submission or IMAP LOGIN interfaces.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ldap-injection
  - authentication-bypass
  - information-disclosure
  - maddy
  - smtp
  - imap
vendors:
  - Maddy
products:
  - Maddy Mail Server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1601
    technique_name: Impersonation
references:
  - https://github.com/advisories/GHSA-5835-4gvc-32pc
rules:
  - title: Detect Maddy LDAP Injection Attempt via SMTP AUTH
    description: Detects attempts to exploit the Maddy LDAP injection vulnerability (CVE-2026-40193) by monitoring for suspicious characters in the username field during SMTP AUTH PLAIN authentication.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1068
      - T1555.002
    data_sources:
      - network_connection
      - linux
  - title: Detect Maddy LDAP Injection Attempt via IMAP LOGIN
    description: Detects attempts to exploit the Maddy LDAP injection vulnerability (CVE-2026-40193) by monitoring for suspicious characters in the username field during IMAP LOGIN authentication.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1068
      - T1555.002
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Maddy is vulnerable to LDAP injection due to the `auth.ldap` module constructing LDAP search filters and DN strings by directly interpolating user-supplied usernames without proper escaping. This vulnerability, present in versions prior to 0.9.3, allows an attacker to inject arbitrary LDAP filter expressions through the username field of the SMTP submission (AUTH PLAIN) or IMAP LOGIN interfaces. Specifically, the `strings.ReplaceAll()` function is used to insert the username into LDAP queries without sanitization. Successful exploitation enables identity spoofing, LDAP directory enumeration, and attribute value extraction. The vulnerable code is located in `internal/auth/ldap/ldap.go` within the `Lookup()` and `AuthPlain()` functions. This vulnerability is identified as CVE-2026-40193.

## Attack Chain

1.  The attacker identifies a Maddy instance configured to use LDAP authentication with the `auth.ldap` module and either the `filter` or `dn_template` directive enabled.
2.  The attacker connects to the Maddy instance's SMTP submission port (587) or IMAP port (993/143).
3.  The attacker initiates the authentication process (AUTH PLAIN for SMTP, LOGIN for IMAP).
4.  The attacker crafts a malicious username containing LDAP injection payloads (e.g., `user)(attribute=value*)`) to bypass authentication or extract information.
5.  The crafted username is passed to the vulnerable `strings.ReplaceAll()` function in `internal/auth/ldap/ldap.go` without proper sanitization.
6.  The unsanitized username is incorporated into an LDAP query or DN string, modifying the query's behavior.
7.  If the injected filter allows, the attacker successfully authenticates as another user or extracts sensitive information via boolean-based blind injection.
8.  The attacker leverages successful LDAP injection to spoof identities, enumerate the LDAP directory, or exfiltrate user attributes.

## Impact

Successful exploitation of this vulnerability can lead to significant consequences. Attackers can spoof identities and potentially gain unauthorized access to resources. LDAP directory enumeration allows attackers to discover sensitive information about users and the directory structure. The ability to extract attribute values, including password hashes, further compromises the security of the system. All maddy deployments using the `auth.ldap` module with the `filter` or `dn_template` directive are vulnerable, affecting both SMTP submission and IMAP authentication. This issue is tracked as CVE-2026-40193 and has a high severity rating.

## Recommendation

*   Upgrade to Maddy version 0.9.3 or later to patch the vulnerability described in GHSA-5835-4gvc-32pc.
*   Deploy the Sigma rule "Detect Maddy LDAP Injection Attempt via SMTP AUTH" to identify attempted exploitation via SMTP AUTH PLAIN.
*   Enable detailed logging on the Maddy server, specifically capturing the usernames used during SMTP AUTH and IMAP LOGIN attempts, to facilitate investigation of potential LDAP injection attacks.
*   If upgrading is not immediately feasible, consider disabling the `auth.ldap` module or implementing input validation to sanitize usernames before they are used in LDAP queries.
