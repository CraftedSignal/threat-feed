---
title: Symfony X509Authenticator Identity Spoofing Vulnerability (CVE-2026-45063)
slug: 2026-05-symfony-x509-auth-bypass
description: Symfony's X509Authenticator is vulnerable to identity spoofing due to an unanchored regex in the extraction of the user identifier from the Subject DN of client certificates, allowing attackers to authenticate as other users by crafting a certificate with a malicious CN value.
date: "2026-05-27T16:52:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - symfony
  - authentication bypass
  - identity spoofing
  - CVE-2026-45063
vendors:
  - Symfony
products:
  - symfony/security-http < 5.4.52
  - symfony/security-http >= 6.0.0-BETA1, < 6.4.40
  - symfony/security-http >= 7.0.0-BETA1, < 7.4.12
  - symfony/security-http >= 8.0.0-BETA1, < 8.0.12
  - symfony/symfony < 5.4.52
  - symfony/symfony >= 6.0.0-BETA1, < 6.4.40
  - symfony/symfony >= 7.0.0-BETA1, < 7.4.12
  - symfony/symfony >= 8.0.0-BETA1, < 8.0.12
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1587
    technique_name: Develop Capabilities
references:
  - https://github.com/advisories/GHSA-ph86-p8f6-f9r2
  - https://github.com/symfony/symfony/commit/ccb3f724c7ff55670a6fe3521c7bf1514cceb478
rules:
  - title: Detect Symfony X509Authenticator Authentication Bypass
    description: Detects CVE-2026-45063 exploitation — Monitors for requests with a manipulated SSL_CLIENT_S_DN value containing 'emailAddress=' within the CN, indicating a potential authentication bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1587.001
    data_sources:
      - webserver
  - title: Detect Suspicious SSL_CLIENT_S_DN Modifications
    description: Detects modification of SSL_CLIENT_S_DN header to include emailAddress within CN RDN
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1587.001
    data_sources:
      - webserver
rules_count: 2
---

The `X509Authenticator` in Symfony versions before 5.4.52, versions between 6.0.0-BETA1 and 6.4.40, versions between 7.0.0-BETA1 and 7.4.12, and versions between 8.0.0-BETA1 and 8.0.12 is susceptible to an identity spoofing vulnerability (CVE-2026-45063). This flaw stems from the use of an unanchored regex when extracting the user identifier from the Subject DN of a client certificate. The `X509Authenticator` implements client-certificate (mTLS) authentication, where the web server validates the client's certificate and then passes the certificate's Subject DN to Symfony via `$_SERVER['SSL_CLIENT_S_DN']`. An attacker who can obtain a certificate from a trusted CA can exploit this vulnerability by embedding a crafted `emailAddress=victim@target` string within the `CN` value of the certificate. This allows the attacker to bypass authentication and impersonate the victim user.

## Attack Chain

1.  Attacker obtains a certificate from a trusted Certificate Authority (CA).
2.  When requesting the certificate, the attacker sets the Common Name (CN) field to include a malicious string like `CN=Attacker emailAddress=victim@example.com,O=AttackerOrg`.
3.  The attacker presents the certificate to a Symfony application configured to use `X509Authenticator` for authentication.
4.  The web server validates the certificate against the trusted CA.
5.  The web server passes the certificate's Subject DN to Symfony via the `$_SERVER['SSL_CLIENT_S_DN']` variable.
6.  Symfony's `X509Authenticator` extracts the user identifier using an unanchored regex.
7.  Due to the unanchored regex, the authenticator incorrectly identifies `victim@example.com` as the user's email address from the CN.
8.  The attacker is authenticated as `victim@example.com`, gaining unauthorized access to the victim's account.

## Impact

Successful exploitation of this vulnerability allows an attacker to impersonate legitimate users on affected Symfony applications. This could lead to unauthorized access to sensitive data, modification of user accounts, or other malicious activities depending on the permissions and roles assigned to the compromised user account. The vulnerability impacts applications using client certificate authentication with the flawed `X509Authenticator` component.

## Recommendation

*   Upgrade `symfony/security-http` and `symfony/symfony` to the latest patched versions (>= 5.4.52, >= 6.4.40, >= 7.4.12, >= 8.0.12) as provided by the vendor to remediate CVE-2026-45063.
*   Deploy the Sigma rule `Detect Symfony X509Authenticator Authentication Bypass` to detect attempts to exploit this vulnerability by monitoring for requests with manipulated SSL_CLIENT_S_DN values.
*   If upgrading is not immediately feasible, consider implementing a temporary workaround by sanitizing the `$_SERVER['SSL_CLIENT_S_DN']` value before it is processed by the `X509Authenticator` to prevent exploitation of the unanchored regex.
