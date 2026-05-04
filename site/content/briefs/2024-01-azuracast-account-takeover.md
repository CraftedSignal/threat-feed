---
title: AzuraCast Account Takeover via X-Forwarded-Host Poisoning
slug: 2024-01-azuracast-account-takeover
description: AzuraCast is vulnerable to password reset poisoning due to unconditionally trusting the X-Forwarded-Host header, allowing an attacker to inject a malicious host into the password reset URL, exfiltrate the reset token, reset the victim's password, and disable 2FA, leading to account takeover.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - account takeover
  - x-forwarded-host
  - password reset poisoning
vendors:
  - nginx
  - composer
products:
  - azuracast
  - nginx
  - azuracast/azuracast (<= 0.23.5)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Impair Defenses
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Personal Credentials
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-gv7r-3mr9-h5x8
iocs:
  - type: domain
    value: evil.com
  - type: email
    value: admin@target.com
ioc_counts:
  domain: 1
  email: 1
rules:
  - title: Detect AzuraCast Password Reset Poisoning Attempt
    description: Detects POST requests to the /forgot endpoint with a suspicious X-Forwarded-Host header, indicating a potential password reset poisoning attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1556.006
    data_sources:
      - webserver
      - linux
  - title: Detect Password Reset Token Retrieval from Evil Domain
    description: Detects requests to attacker-controlled domains for password reset tokens.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1556.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AzuraCast versions 0.23.5 and earlier are vulnerable to an account takeover vulnerability stemming from the unconditional trust of the `X-Forwarded-Host` HTTP header. An unauthenticated attacker can exploit this by injecting a malicious hostname into the password reset URL sent to a user. This is achieved by sending a crafted request to the `/forgot` endpoint with the `X-Forwarded-Host` header set to a domain controlled by the attacker. The victim, upon clicking the poisoned link in the reset email, inadvertently sends their password reset token to the attacker's server. This allows the attacker to reset the victim's password and disable their two-factor authentication, gaining complete control of the account. This vulnerability exists because the `ApplyXForwarded` middleware doesn't validate the `X-Forwarded-Host` header against a trusted proxy allowlist and the application uses the request host for generating security-critical URLs.

## Attack Chain

1.  The attacker crafts a POST request to the `/forgot` endpoint with the `X-Forwarded-Host` header set to a malicious domain (e.g., `evil.com`).
2.  The AzuraCast application generates a password reset email containing a poisoned URL with the attacker's domain.
3.  The victim receives the password reset email and clicks on the malicious link, sending a GET request to the attacker's domain, inadvertently leaking the password reset token.
4.  The attacker's server captures the password reset token from the URL path.
5.  The attacker uses the captured token to access the password reset page on the legitimate AzuraCast instance.
6.  The attacker obtains a CSRF token from the reset page.
7.  The attacker crafts a POST request to the password reset endpoint on the real AzuraCast instance, including the CSRF token and a new password.
8.  The victim's password is changed, and their 2FA is disabled, granting the attacker full account access.

## Impact

Successful exploitation of this vulnerability allows for full account takeover of any user, including administrators, without prior authentication. The attack also bypasses 2FA, negating its security benefits. If an administrator account is compromised, the attacker gains full control of the AzuraCast instance, including all stations, media, and system settings. The attack requires the victim to click a link in a legitimate-looking password reset email, increasing the likelihood of success. This can lead to unauthorized access to sensitive data, disruption of service, and reputational damage.

## Recommendation

*   Implement a trusted proxy allowlist in `backend/src/Middleware/ApplyXForwarded.php` to validate the `X-Forwarded-Host` header, as described in the provided fix, to prevent hostname injection (Fix 1).
*   Modify `ForgotPasswordAction.php` to generate the reset URL using the configured `base_url` setting rather than the request-derived URL to ensure the correct domain is used in the reset email (Fix 2).
*   Deploy the following Sigma rule to detect suspicious requests to the `/forgot` endpoint with a non-standard `X-Forwarded-Host` header to identify potential exploitation attempts.
*   Remove the line `$user->two_factor_secret = null;` from `LoginTokenAction.php:75` to prevent 2FA from being disabled during password reset, requiring a separate, explicit flow for 2FA recovery (Fix 3).
