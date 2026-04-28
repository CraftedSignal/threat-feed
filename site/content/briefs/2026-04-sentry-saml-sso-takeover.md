---
title: Sentry SAML SSO Improper Authentication Vulnerability
slug: 2026-04-sentry-saml-sso-takeover
description: A critical vulnerability in Sentry's SAML SSO implementation allows account takeover by exploiting improper authentication when multiple organizations are configured, affecting versions 21.12.0 to 26.2.0 and requiring a malicious SAML Identity Provider and knowledge of the victim's email address.
date: "2026-04-18T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - sentry
  - saml
  - sso
  - authentication
  - account-takeover
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
cves:
  - id: CVE-2026-27197
    cvss: 9.1
    epss: 0.00059
references:
  - https://github.com/advisories/GHSA-ggmg-cqg6-j45g
  - https://sentry.io/settings/account/security/
  - https://sentry.zendesk.com/hc/en-us/articles/46773315774235-How-do-I-enable-two-factor-authentication-2FA-on-my-Sentry-account
rules:
  - title: Detect Suspicious SAML Authentication
    description: Detects suspicious SAML authentication attempts based on unusual IP addresses or user agents. This requires Sentry audit logs with detailed authentication information.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
  - title: Detect Modification of SENTRY_SINGLE_ORGANIZATION Setting
    description: Detects attempts to modify the SENTRY_SINGLE_ORGANIZATION setting, which is a prerequisite for exploiting the SAML SSO vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability (CVE-2026-27197) has been identified in the SAML Single Sign-On (SSO) implementation within Sentry, a popular error tracking and performance monitoring platform. This vulnerability allows a malicious actor to potentially take over user accounts by leveraging a rogue SAML Identity Provider (IdP) in conjunction with another organization configured within the same Sentry instance. The attacker needs to know the victim's email address for successful exploitation. This flaw primarily impacts self-hosted Sentry deployments with multiple organizations enabled (SENTRY_SINGLE_ORGANIZATION = False) and where a malicious user possesses the ability to modify SSO settings for another organization. Sentry SaaS was patched on February 18, 2026. Self-hosted users should upgrade to version 26.2.0 or later to remediate this vulnerability.

## Attack Chain

1.  The attacker gains access to a Sentry instance that hosts multiple organizations. This could be through compromised credentials or other initial access vectors.
2.  The attacker identifies a target user's email address within the Sentry instance.
3.  The attacker gains permissions to modify SSO settings for an organization within the Sentry instance.
4.  The attacker configures a malicious SAML Identity Provider (IdP) for the organization they control. This IdP is designed to spoof user identities.
5.  The victim attempts to log in to Sentry via SAML SSO.
6.  Sentry redirects the victim to the attacker's malicious SAML IdP for authentication.
7.  The attacker's malicious SAML IdP asserts the victim's identity (using the known email address) to Sentry, but the assertion is illegitimate and controlled by the attacker.
8.  Sentry, due to the vulnerability, improperly validates the SAML assertion, allowing the attacker to successfully authenticate as the victim and gain unauthorized access to their account.

## Impact

Successful exploitation of this vulnerability allows an attacker to completely take over a targeted user's Sentry account. This grants the attacker the ability to access sensitive project data, modify configurations, invite/remove team members, and potentially disrupt the entire Sentry instance's operations. The vulnerability affects Sentry versions 21.12.0 up to, but not including, 26.2.0. The number of potential victims depends on the number of vulnerable Sentry instances with multiple organizations configured and the attacker's ability to modify SSO settings.

## Recommendation

*   Upgrade self-hosted Sentry instances to version 26.2.0 or later to patch CVE-2026-27197.
*   Enable two-factor authentication (2FA) on all Sentry accounts. Users can manage this in Account Settings > Security, as mentioned in the [helpdesk article](https://sentry.zendesk.com/hc/en-us/articles/46773315774235-How-do-I-enable-two-factor-authentication-2FA-on-my-Sentry-account).
*   Monitor Sentry logs for unusual SSO configuration changes, specifically modifications to SAML Identity Provider settings. Deploy a rule that detects modifications to the `SENTRY_SINGLE_ORGANIZATION` setting, as this is a prerequisite for exploitation.
*   Implement the Sigma rule `Detect Suspicious SAML Authentication` to identify potential unauthorized SAML authentication attempts based on unusual IP addresses or user agents.
