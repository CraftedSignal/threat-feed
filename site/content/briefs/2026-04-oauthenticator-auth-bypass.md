---
title: OAuthenticator Authentication Bypass Vulnerability (CVE-2026-33175)
slug: 2026-04-oauthenticator-auth-bypass
description: OAuthenticator versions prior to 17.4.0 contain an authentication bypass vulnerability (CVE-2026-33175) that allows an attacker with an unverified email address on an Auth0 tenant to log in to JupyterHub when email is used as the username claim, potentially leading to account takeover.
date: "2026-04-03T22:16:26Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - authentication-bypass
  - jupyterhub
  - oauthenticator
  - cve-2026-33175
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33175
  - https://github.com/jupyterhub/oauthenticator/commit/f0c7002dc36e41efae0f674033cf7888a21d96f9
  - https://github.com/jupyterhub/oauthenticator/releases/tag/17.4.0
  - https://github.com/jupyterhub/oauthenticator/security/advisories/GHSA-rrvg-cxh4-qhrv
rules:
  - title: Detect JupyterHub Process Creation After Successful Auth0 Authentication
    description: Detects suspicious process creation events on a JupyterHub server shortly after a successful authentication event from Auth0, which may indicate exploitation of CVE-2026-33175.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1190
      - T1555
    data_sources:
      - process_creation
      - linux
  - title: Detect Account Takeover via Auth0 Unverified Email on JupyterHub
    description: Detects potential account takeover attempts via Auth0 accounts with unverified email addresses on JupyterHub instances.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OAuthenticator is a software package that enables the integration of OAuth2 identity providers with JupyterHub. A critical authentication bypass vulnerability, identified as CVE-2026-33175, affects OAuthenticator versions prior to 17.4.0. This flaw permits an attacker with an unverified email address on an Auth0 tenant to successfully authenticate and log in to a JupyterHub instance. The vulnerability arises when email is used as the `username_claim`, granting attackers control over their username and potentially enabling account takeover. Organizations using affected versions of OAuthenticator in conjunction with Auth0 are at risk. The vulnerability was patched in version 17.4.0.

## Attack Chain

1.  Attacker gains access to an Auth0 tenant and creates an account.
2.  The attacker does not verify the email address associated with the Auth0 account.
3.  JupyterHub is configured to use OAuthenticator for authentication, with email specified as the `username_claim`.
4.  The attacker attempts to log in to JupyterHub using the unverified Auth0 account.
5.  Due to the vulnerability in OAuthenticator versions prior to 17.4.0, the authentication bypass occurs, allowing the attacker to successfully log in.
6.  The attacker gains unauthorized access to the JupyterHub environment.
7.  Attacker leverages the compromised account to perform malicious activities, such as accessing sensitive data or modifying Jupyter notebooks.

## Impact

Successful exploitation of CVE-2026-33175 allows unauthorized access to JupyterHub instances. This can lead to the compromise of sensitive data, modification of Jupyter notebooks, and potential disruption of services. The vulnerability impacts organizations that use OAuthenticator with Auth0 and rely on email as the username claim. The number of affected organizations is currently unknown.

## Recommendation

*   Upgrade OAuthenticator to version 17.4.0 or later to patch CVE-2026-33175.
*   Review JupyterHub configurations to ensure that email is not used as the `username_claim` if possible.
*   Implement multi-factor authentication (MFA) for JupyterHub accounts to mitigate the risk of account takeover.
*   Monitor logs for suspicious login attempts from Auth0 accounts with unverified email addresses. Deploy the provided Sigma rule targeting process creation after successful authentication to detect suspicious activity.
