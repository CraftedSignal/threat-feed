---
title: SolarWinds Web Help Desk SAML Authentication Bypass
slug: 2026-07-solarwinds-whd-saml-bypass
description: SolarWinds Web Help Desk versions 2026.1 and prior are vulnerable to a critical authentication bypass via the SAML 2.0 implementation, allowing unauthenticated remote access.
date: "2026-07-30T17:29:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - saml
  - vulnerability
  - cve-2026-28323
vendors:
  - SolarWinds
products:
  - Web Help Desk
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: SolarWinds Web Help Desk is found to be affected by a SAML authentication bypass vulnerability.
    confidence_band: high
cves:
  - id: CVE-2026-28323
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28323
  - https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28323
  - https://documentation.solarwinds.com/en/success_center/whd/content/release_notes/whd_2026-2-1_release_notes.htm
---

SolarWinds has disclosed a critical authentication bypass vulnerability, tracked as CVE-2026-28323, affecting the Web Help Desk (WHD) application. The vulnerability resides in the SAML 2.0 authentication integration. If SAML 2.0 authentication is enabled within the application settings, an unauthenticated remote attacker can bypass the standard login flow to gain unauthorized access to the system. This vulnerability has been assigned a CVSS v3.1 score of 9.8, reflecting its critical impact. The flaw affects Web Help Desk version 2026.1 and all preceding versions. Defenders must verify the current version of their WHD instances and ensure that those utilizing SAML for authentication are patched or secured according to vendor guidance.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing SolarWinds Web Help Desk instances.
2. Attacker probes the application to confirm if SAML 2.0 authentication is enabled.
3. Attacker crafts a malicious or crafted SAML assertion or bypass request targeting the WHD authentication endpoint.
4. The application improperly validates the SAML response or authentication state, granting the attacker an authenticated session.
5. Attacker gains unauthorized access to the Web Help Desk administrative or user interface.
6. Attacker leverages this access to perform internal actions, potentially including data exfiltration or system modification depending on the privileges of the hijacked session.

## Impact

Successful exploitation allows an unauthenticated attacker to gain unauthorized access to the SolarWinds Web Help Desk instance. This may lead to the exposure of sensitive help desk tickets, internal user information, and potential administrative control over the help desk infrastructure. The vulnerability affects all organizations utilizing WHD with SAML 2.0 enabled, creating a significant risk of data breach and unauthorized system manipulation.

## Recommendation

- Upgrade to SolarWinds Web Help Desk version 2026.2.1 or later to remediate CVE-2026-28323.
- Audit web server and application access logs for unusual patterns of authentication attempts directed at the SAML callback or login endpoints.
- Monitor for anomalous administrative activities occurring from unexpected user sessions or source IP addresses within the help desk application.
- Review the SolarWinds security advisory for CVE-2026-28323 and follow recommended hardening steps for Web Help Desk configurations.
