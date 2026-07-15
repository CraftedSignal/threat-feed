---
title: B2B Platform Paywall Bypass via Client-Side Boolean Manipulation
slug: 2026-07-b2b-platform-logic-flaw
description: 'An autonomous Red Agent discovered a critical business-logic flaw in a B2B platform''s data API, allowing free-tier users to bypass the paywall and access premium, unmasked contact data for over 600 million profiles by adding a boolean flag, `unmaskContactData: true`, to standard API requests, due to the backend accepting client-controlled parameters without verifying user entitlements.'
date: "2026-07-15T15:29:51Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Red Agent
tags:
  - business-logic-flaw
  - authorization-bypass
  - api-security
  - red-team
  - data-collection
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Red Agent scanned an B2B platform that holds hundreds of millions of business emails and verified phone numbers and discovered an authorization bypass that allowed free-tier users to access unmasked contact data without paying for it.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: The system returned fully unmasked business emails, direct phone lines, and associated personal email addresses in cleartext.
    confidence_band: high
references:
  - https://www.wiz.io/blog/red-agent-pov-business-logic
---

Wiz's "Red Agent," an autonomous AI pentesting system, identified a critical business-logic flaw within a leading B2B platform's data API. This vulnerability allowed any free-tier user to bypass the platform's paywall and access premium, unmasked contact information for over 600 million profiles without expending credits. The flaw stemmed from the backend's failure to validate user entitlements before honoring a client-controlled parameter, `unmaskContactData: true`, which was meant to be exclusive to paid tiers. This misconfiguration meant the server implicitly trusted client input, enabling widespread data exfiltration by manipulating a single boolean value in API requests. The platform's security team promptly remediated the issue within hours of the report.

## Attack Chain

1. **Reconnaissance and Bundle Analysis:** The Red Agent began by mapping the application's API surface, analyzing over 130MB of client-side JavaScript bundles to extract over 100 distinct API endpoint paths, including internal data operations.
2. **API Endpoint Identification:** Specific internal data API endpoints were identified, such as `POST /api/internal/data/hPeopleSearch`, `POST /api/internal/data/hPersonLookup`, and `POST /api/internal/data/hUnifiedSearch`.
3. **Hypothesis Generation & Schema Reverse-Engineering:** Through analysis of request/response schemas embedded in the frontend codebase, the agent identified a boolean parameter, `unmaskContactData`, which was referenced in the code but not used in standard free-tier search flows.
4. **Formulation of Hypothesis:** The agent hypothesized that because the frontend was aware of this flag, the backend likely accepted it, and tested whether the server would validate user entitlements before honoring the flag, or blindly trust client input.
5. **Baseline Measurement:** A normal search request was performed from a free-tier account, confirming that data masking was active and functioning as intended under standard operations.
6. **Exploitation via Parameter Injection:** The agent replayed the exact same search request but injected the `unmaskContactData: true` flag into the JSON payload of the API request.
7. **Authorization Bypass:** The server accepted the injected flag without checking the user's credit balance or tier entitlements, returning the records fully unmasked, thus bypassing the paywall.

## Impact

The identified business logic flaw allowed free-tier users to access critical, unmasked data for over 600 million business profiles. This included business email addresses for all 600 million contacts, over 135 million verified direct phone numbers, personal email addresses for approximately 50% of records, and comprehensive company intelligence (revenue, headcount, addresses). The vulnerability fundamentally compromised the platform's primary authorization and monetization controls, enabling data to be retrieved at scale without payment. While quickly remediated by the platform's security team, such a flaw could lead to massive data exposure, reputational damage, and significant financial losses if exploited by malicious actors.

## Recommendation

* Implement rigorous server-side validation for all client-controlled parameters, especially those that influence data access or authorization, to prevent authorization bypasses as observed with the `unmaskContactData` parameter.
* Conduct thorough security reviews and penetration testing specifically targeting business logic flaws, as traditional SAST/DAST tools often miss these subtle vulnerabilities.
* Ensure that all entitlement, pricing, and access decisions are enforced server-side, per record, and are never inferred or solely reliant on client-side input.
* Deploy API gateway or WAF logging capable of inspecting HTTP request bodies for unusual parameters or patterns, which would be necessary to detect `unmaskContactData: true` injections.
