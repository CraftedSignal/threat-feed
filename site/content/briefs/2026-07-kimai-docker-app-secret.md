---
title: Kimai Docker Image Default APP_SECRET Allows Account Takeover (CVE-2026-52824)
slug: 2026-07-kimai-docker-app-secret
description: A critical vulnerability, CVE-2026-52824, in the official Kimai Docker image allows unauthenticated attackers to forge authentication tokens and achieve account takeover, including super_admin accounts, due to the image shipping with a default, publicly known APP_SECRET environment variable used by Symfony to HMAC-sign session cookies and login links.
date: "2026-07-14T00:08:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - web-application
  - misconfiguration
  - account-takeover
  - docker
vendors:
  - Kimai
products:
  - Kimai (Docker image)
  - composer/kimai/kimai (<= 2.57.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker who can reach the Kimai URL can forge authentication tokens and log in as any user
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The official Kimai Docker image ships with `APP_SECRET=change_this_to_something_unique` as the default environment variable.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: take over any account including super_admin.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-jr9p-4h4j-6c58
  - https://www.kimai.org/en/security/ghsa-jr9p-4h4j-6c58
---

A critical vulnerability (CVE-2026-52824) affects the official Kimai Docker image, enabling unauthenticated attackers to achieve full account takeover. The root cause is the Docker image shipping with a hardcoded `APP_SECRET=change_this_to_something_unique` environment variable, which is a known secret. This `APP_SECRET` is used by the underlying Symfony framework to HMAC-sign sensitive data such as the `KIMAI_REMEMBER` cookie, login links, and password reset URLs. If a Kimai instance is deployed via Docker without explicitly overriding this default `APP_SECRET`, an attacker can leverage this known value to forge valid authentication tokens. This allows them to bypass authentication and log in as any user, including `super_admin`, provided the attacker knows the username, can guess the sequential user ID, and the target account does not have 2FA enabled. The vulnerability affects Kimai versions up to and including 2.57.0.

## Attack Chain

1. **Reconnaissance**: An unauthenticated attacker identifies an internet-exposed Kimai instance.
2. **Vulnerability Identification**: The attacker determines that the Kimai instance is running the official Docker image with the default, known `APP_SECRET`.
3. **Target Identification**: The attacker identifies a target username (e.g., `super_admin`) and guesses the corresponding sequential user ID (often 1 for the initial admin account).
4. **Token Forgery**: Using the publicly known default `APP_SECRET` (`change_this_to_something_unique`), the attacker crafts a valid HMAC-signed `KIMAI_REMEMBER` cookie or a login link URL for the target user ID.
5. **Authentication Bypass**: The attacker sends the forged cookie in an HTTP request to the Kimai instance or navigates directly to the forged login link.
6. **Account Takeover**: The vulnerable Kimai instance validates the forged cookie or login link using the default `APP_SECRET` and grants the attacker authenticated access to the target user's account without requiring valid credentials.
7. **Post-Exploitation**: The attacker gains full control over the compromised user's account, potentially performing further actions like privilege escalation, data exfiltration, or establishing additional persistence.

## Impact

Any Kimai instance deployed via its official Docker image without overriding the default `APP_SECRET` is critically vulnerable to unauthenticated account takeover. An attacker can compromise `super_admin` accounts, leading to full control over the Kimai application, its data, and potentially integrated systems. This can result in unauthorized access to sensitive project and user data, manipulation of timesheets, or disruption of business operations. The attacker only needs to know a username, guess a sequential user ID, and the account must not have active two-factor authentication. This vulnerability affects a broad range of organizations using Kimai for time tracking and project management.

## Recommendation

* **Patch CVE-2026-52824**: Immediately update all Kimai instances to a patched version (newer than 2.57.0), which includes updates to `entrypoint.sh` to generate a random `APP_SECRET` and removes the default from the Dockerfile.
* **Configure APP_SECRET**: For all Kimai Docker deployments, explicitly set a unique and strong `APP_SECRET` environment variable using Docker secrets or Kubernetes secrets management. Do not rely on the default value.
* **Review Documentation**: Refer to the updated Kimai security documentation (linked in references) for best practices regarding `APP_SECRET` configuration.
* **Enable Multi-Factor Authentication**: For critical accounts, enable 2FA where available to add an additional layer of security, as the attack is mitigated if 2FA is active.
