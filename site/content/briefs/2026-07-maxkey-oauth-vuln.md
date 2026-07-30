---
title: Insufficient Redirect URI Validation in MaxKey
slug: 2026-07-maxkey-oauth-vuln
description: MaxKey versions through 4.1.12 are vulnerable to OAuth 2.0 authorization code hijacking due to improper host boundary checks in the DefaultRedirectResolver component.
date: "2026-07-30T15:33:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - oauth
  - identity-management
  - cve-2026-67345
vendors:
  - MaxKey
products:
  - MaxKey (4.1.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers who control a domain ending with the registered redirect URI hostname can social-engineer victims into clicking a crafted authorization URL.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
    evidence: causing the authorization code to be issued to the attacker-controlled URI and exchanged for an access token granting access to the victim's identity.
    confidence_band: high
cves:
  - id: CVE-2026-67345
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67345
---

MaxKey versions through 4.1.12 contain a security vulnerability in the DefaultRedirectResolver.hostMatches() method. The issue stems from insufficient validation of redirect URIs during the OAuth 2.0 authorization process. Specifically, the application fails to enforce proper dot-boundary anchoring when comparing the provided redirect_uri against registered URIs. This flaw allows an attacker to supply a crafted redirect_uri that shares a hostname suffix with a legitimate registered URI, effectively bypassing validation checks. By utilizing social engineering to entice a victim to initiate an authorization request via a malicious link, an attacker can cause the authorization server to send the authorization code to an attacker-controlled endpoint. The attacker then exchanges this code for an access token, resulting in unauthorized access to the victim's account and identity. Organizations using MaxKey 4.1.12 or earlier should apply the fix provided in commit ddbb72f.

## Impact

Successful exploitation allows remote, unauthenticated attackers to hijack OAuth 2.0 authorization codes. This leads to the unauthorized acquisition of access tokens, enabling the attacker to impersonate the victim, access protected resources, and potentially escalate privileges within the environment. This affects all deployments of MaxKey relying on the standard OAuth 2.0 authorization flow.

## Recommendation

* Upgrade MaxKey instances to a version containing the fix for CVE-2026-67345 (commit ddbb72f).
* Review application logs for unusual redirect_uri patterns in OAuth authorization requests, specifically checking for domains that match the suffix of authorized clients without proper sub-domain or TLD isolation.
* Audit all registered OAuth 2.0 client redirect URIs in MaxKey to ensure they are fully qualified and follow strict matching standards.
