---
title: Sentry SAML SSO Improper Authentication Vulnerability
slug: 2026-04-sentry-saml-sso-takeover
description: A critical vulnerability in Sentry's SAML SSO implementation allows account takeover by exploiting improper authentication when multiple organizations are configured, affecting versions 21.12.0 to 26.2.0 and requiring a malicious SAML Identity Provider and knowledge of the victim's email address.
date: "2026-04-18T12:00:00Z"
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

A critical vulnerability (CVE-2026-27197) has been identified in the SAML Single Sign-On (SSO) implementation within Sentry, a popular error tracking and performance monitoring platform. This vulnerability allows a malicious actor to potentially take over user accounts by leveraging a rogue SAML Identity Provider (IdP) in conjunction with another organization configured within the same Sentry instance. The attacker needs to know the victim's email address for successful exploitation. This flaw…
