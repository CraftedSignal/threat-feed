---
title: SigNoz Open Redirect Vulnerability Allows Session Token Theft (CVE-2026-63094)
slug: 2026-07-signoz-open-redirect
description: An open redirect vulnerability exists in SigNoz through version 0.133.0 within its SSO authentication flow, affecting instances configured with Google OAuth, SAML, or OIDC. Unauthenticated attackers can exploit this by crafting a login URL with a malicious `ref` parameter pointing to an attacker-controlled host. By delivering this crafted URL to a victim, attackers can steal the victim's access and refresh tokens upon successful SSO authentication, leading to session compromise.
date: "2026-07-17T15:18:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - open-redirect
  - sso
  - vulnerability
  - web-application
  - credential-theft
vendors:
  - SigNoz
products:
  - SigNoz <= 0.133.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SigNoz through 0.133.0 contains an open redirect vulnerability in the SSO authentication flow that allows unauthenticated attackers to steal session tokens.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can [...] receive the victim's access and refresh tokens when they complete SSO authentication.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
cves:
  - id: CVE-2026-63094
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63094
---

An open redirect vulnerability, identified as CVE-2026-63094, has been discovered in SigNoz versions up to and including 0.133.0. This flaw affects instances configured to use Single Sign-On (SSO) authentication methods such as Google OAuth, SAML, or OIDC. Unauthenticated attackers can leverage this vulnerability by crafting a specific login URL containing a malicious `ref` parameter. This parameter, when exploited, directs the victim to an attacker-controlled host after they complete a legitimate SSO authentication process. The primary objective of this attack is to steal the victim's session tokens, including access and refresh tokens, which could then be used to impersonate the user and gain unauthorized access to their SigNoz instance and potentially other linked services. The absence of proper validation for the `ref` parameter in the SSO authentication flow is the root cause, making this a critical concern for defenders, as it allows for easy credential harvesting.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable SigNoz instance configured with Google OAuth, SAML, or OIDC.
2. The attacker crafts a malicious URL for the "unauthenticated sessions context endpoint" within SigNoz, embedding a `ref` parameter that points to an attacker-controlled domain.
3. The attacker delivers this crafted URL to a target victim, typically via social engineering tactics such as phishing.
4. The victim clicks the malicious URL, which initiates the legitimate SigNoz SSO authentication flow.
5. The victim successfully completes the SSO authentication process with their identity provider (e.g., Google, Okta).
6. Upon successful authentication, the SigNoz application, due to the open redirect vulnerability, redirects the victim's browser to the attacker-controlled domain specified in the `ref` parameter.
7. The attacker's server captures the victim's session tokens (access and refresh tokens) that are sent during the redirection process, leading to session compromise.

## Impact

The successful exploitation of CVE-2026-63094 allows unauthenticated attackers to steal session tokens (both access and refresh tokens) from any user on affected SigNoz instances utilizing SSO. This compromises the integrity of user sessions, granting attackers unauthorized access to the victim's SigNoz environment. Depending on the privileges of the compromised account and the configuration of the SigNoz instance, attackers could view sensitive data, manipulate monitoring configurations, or potentially move laterally within the organization's infrastructure if SigNoz is integrated with other systems. The specific number of affected organizations or users is not disclosed, but any organization using SigNoz through version 0.133.0 with SSO enabled is at risk.

## Recommendation

* Patch CVE-2026-63094 immediately by updating SigNoz to a version beyond 0.133.0 as soon as a fix is available from the vendor.
* Review web server access logs for any suspicious HTTP requests to the "unauthenticated sessions context endpoint" containing `ref` parameters that point to unfamiliar or external domains, as this could indicate attempted exploitation.
* Implement security awareness training for users to recognize and avoid phishing attempts involving suspicious login URLs, which is the primary delivery mechanism for this threat.
