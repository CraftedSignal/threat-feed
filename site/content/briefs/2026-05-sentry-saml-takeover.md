---
title: Sentry SAML SSO Improper Authentication Allows User Identity Linking
slug: 2026-05-sentry-saml-takeover
description: A critical vulnerability (CVE-2026-42354) exists in Sentry's SAML SSO implementation that allows an attacker to take over any user account by using a malicious SAML Identity Provider and another organization on the same Sentry instance, affecting self-hosted users with multiple organizations configured if a malicious user has permissions to modify SSO settings, while Sentry SaaS was patched in April and self-hosted users are advised to upgrade to version 26.4.1 or higher.
date: "2026-04-30T20:45:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - authentication
  - saml
  - sso
  - account takeover
  - vulnerability
vendors:
  - Sentry
products:
  - sentry
  - Sentry SaaS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Account
references:
  - https://github.com/advisories/GHSA-rcmw-7mc7-3rj7
  - https://github.com/getsentry/sentry/pull/113720
  - https://sentry.io/settings/account/security/
  - https://sentry.zendesk.com/hc/en-us/articles/46773315774235-How-do-I-enable-two-factor-authentication-2FA-on-my-Sentry-account
rules:
  - title: Detect Modifications to SAML SSO Configuration
    description: Detects changes to SAML SSO configuration settings, potentially indicating malicious activity related to CVE-2026-42354 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1550.003
    data_sources:
      - webserver
      - linux
  - title: Detect Failed SAML SSO Authentication Attempts
    description: Detects a surge of failed SAML SSO authentication attempts, potentially indicating a brute-force or account takeover attempt related to CVE-2026-42354.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1550.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-42354, has been identified in the SAML Single Sign-On (SSO) implementation of Sentry, potentially allowing an attacker to compromise user accounts. This vulnerability stems from improper authentication during the SAML SSO process, leading to the possibility of user identity linking. The vulnerability affects Sentry versions 21.12.0 up to and including 26.4.0. To exploit this vulnerability, an attacker requires a malicious SAML Identity Provider and access to another organization within the same Sentry instance, coupled with knowledge of the victim's email address. This attack vector poses a significant risk to self-hosted Sentry instances that are configured with multiple organizations (SENTRY_SINGLE_ORGANIZATION = False), where a malicious user possesses the necessary permissions to modify SSO settings for a different organization. Sentry SaaS has already been patched in April.

## Attack Chain

1.  The attacker gains access to a Sentry instance that has multiple organizations configured.
2.  The attacker obtains permissions to modify the SAML SSO settings of at least one organization within the Sentry instance.
3.  The attacker crafts a malicious SAML Identity Provider (IdP) designed to inject or manipulate user identity attributes.
4.  The attacker uses the malicious SAML IdP to initiate a single sign-on (SSO) process to a Sentry organization they control.
5.  The attacker provides the email address of the targeted victim, linking the victim's identity in the Sentry instance to the malicious SAML IdP.
6.  The victim attempts to log in to their Sentry account through SAML SSO.
7.  Due to the vulnerability, Sentry incorrectly authenticates the victim based on the attributes provided by the attacker's malicious SAML IdP.
8.  The attacker successfully takes over the victim's account, gaining access to sensitive data and functionalities associated with the victim's privileges.

## Impact

Successful exploitation of this vulnerability can lead to complete account takeover, resulting in unauthorized access to sensitive project data, configuration settings, and potentially even administrative privileges within the Sentry instance. This poses a substantial risk to organizations using vulnerable Sentry versions, as attackers could exfiltrate sensitive information, modify configurations, or disrupt services. The impact is particularly severe for self-hosted Sentry instances with multiple organizations, where a single compromised account could lead to broader access across the entire platform.

## Recommendation

*   Upgrade self-hosted Sentry instances to version 26.4.1 or higher to patch CVE-2026-42354.
*   Enable user account-based two-factor authentication (2FA) for all Sentry accounts as a preventative measure, as mentioned in the Workarounds section.
*   Monitor Sentry audit logs for any unauthorized changes to SAML SSO configurations, particularly within multi-organization setups, to detect potential exploitation attempts.
*   Review and restrict permissions for modifying SSO settings across all organizations to minimize the attack surface, as described in the Overview.
