---
brief_id: brief-2026-11-10-supertokens-saml-replay
event_id: brief-2026-11-10-supertokens-saml-replay
revision: 1
activity_at: "2026-11-10T20:36:48Z"
title: 'SuperTokens Core: SAML Authentication Replay Vulnerability (CVE-2026-123801)'
slug: 2026-11-supertokens-saml-replay
description: SuperTokens Core fails to properly validate SAML assertions, allowing for replay attacks and identity spoofing in specific configurations.
date: "2026-11-10T20:36:48Z"
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
cpes:
  - cpe:2.3:a:supertokens:core:*:*:*:*:*:*:*:*
vendors:
  - SuperTokens
products:
  - SuperTokens Core (11.3.0-11.3.7)
cves:
  - id: CVE-2026-123801
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123801
---

SuperTokens Core versions 11.3.0 through 11.3.7, 11.4.0 through 11.4.7, 12.0.0 through 12.0.10, 12.1.0 through 12.1.1, 12.2.0, and 12.3.0 are vulnerable to SAML assertion replay and identity spoofing. The `SAML.handleCallback` function does not consume RelayState, record assertion identifiers, or enforce `Response.InResponseTo`. 

In SP-initiated flows, attackers can resubmit valid SAML responses to `/recipe/saml/callback` before the `NotOnOrAfter` time. In IdP-initiated flows, assertions can be replayed without RelayState. Additionally, missing checks for `Destination`, `SubjectConfirmationData` `Recipient`, and `NotOnOrAfter` allow accepted callbacks to mint new authorization codes. The application also fails to enforce `allowIDPInitiatedLogin=false`.
