---
brief_id: brief-2026-11-05-keycloak-account-takeover
event_id: brief-2026-11-05-keycloak-account-takeover
revision: 1
activity_at: "2026-11-05T22:33:23Z"
title: 'Keycloak: Account takeover via idp-auto-link authentication (CVE-2026-97175)'
slug: 2026-11-keycloak-account-takeover
description: A flaw in Keycloak’s idp-auto-link authenticator allows attackers to perform account takeover by linking external identities to local accounts using unverified email addresses.
date: "2026-11-05T22:33:23Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Keycloak
cves:
  - id: CVE-2026-97175
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97175
---

CVE-2026-97175 is a security flaw in the idp-auto-link authenticator of the keycloak-services component, which handles user identity federation. The vulnerability occurs when Keycloak automatically links an incoming identity from an external provider to an existing local account based on an email address without verifying if the provider has validated that email.

## Impact
An attacker can take over a victim's account by using a matching unverified email address at a brokered provider.
