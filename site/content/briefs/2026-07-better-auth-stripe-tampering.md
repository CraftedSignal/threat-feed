---
title: Authorization Bypass in @better-auth/stripe Allows Cross-Organization Billing Tampering
slug: 2026-07-better-auth-stripe-tampering
description: An authorization bypass vulnerability in the `@better-auth/stripe` library allows authenticated users to perform subscription actions (cancel, change plan, restore, open billing portal) against other organizations they are a member of, but not authorized to manage. This occurs due to inconsistent handling of organization IDs between the middleware, which approves the ID from the request query string, and the route handler, which acts on the active organization ID from the session or request body. This flaw enables users to access sensitive billing details and manipulate subscriptions for unintended organizations.
date: "2026-07-24T15:46:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - web-application
  - supply-chain
  - application-library
vendors:
  - better-auth
products:
  - '@better-auth/stripe (>= 1.4.11, < 1.6.21)'
  - '@better-auth/stripe (>= 1.7.0-beta.0, < 1.7.0-beta.10)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1561
    technique_name: Disk Wipe
    evidence: An org subscription action can run against the wrong org. The actions are cancel, change plan, restore, and open the billing portal.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Through the billing portal, a member can reach another org's billing details. This includes payment methods, invoices, and subscription state.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-h3rm-78g3-j7cp
---

A high-severity authorization bypass vulnerability exists in the `@better-auth/stripe` library, specifically affecting versions 1.4.11 through 1.6.20 (stable) and 1.7.0-beta.0 through 1.7.0-beta.9 (beta). This flaw allows authenticated users to perform unauthorized subscription actions, such as canceling, changing plans, restoring subscriptions, or accessing the billing portal, for organizations they are a member of but not explicitly authorized to manage. The vulnerability stems from an inconsistency in how organization IDs are handled between the library's middleware and its route handler. The middleware, responsible for authorization, approves an organization ID provided in the request query string, while the route handler, which executes the action, defaults to using the active organization ID from the user's session if no ID is present in the request body. This discrepancy enables an attacker to bypass authorization checks and manipulate billing for an unintended organization, potentially leading to financial damage and sensitive data exposure.

## Attack Chain

1. An attacker, possessing a valid user account, authenticates to an application using the vulnerable `@better-auth/stripe` library.
2. The attacker is a member of at least two organizations (e.g., Organization A and Organization B), where they are authorized to manage billing for Organization A but not Organization B.
3. The attacker intends to perform an unauthorized subscription action (e.g., cancel a subscription) on Organization B.
4. The attacker crafts an HTTP request for a subscription action, including Organization A's ID in the request's query string (e.g., `?orgId=OrgA_ID`).
5. The crafted request deliberately omits Organization B's ID from the request body or sends an empty body.
6. The `@better-auth/stripe` middleware processes the request, validating the `OrgA_ID` from the query string via the `authorizeReference` callback, thereby approving the request.
7. The request proceeds to the route handler. Since no organization ID is found in the request body, the handler defaults to using the attacker's `session.activeOrganizationId`, which is set to `OrgB_ID`.
8. The subscription action is then executed against Organization B, allowing the attacker to manipulate its billing or access its sensitive billing details without proper authorization.

## Impact

Successful exploitation of this vulnerability enables an authenticated user to perform unauthorized subscription actions, including cancellation, plan changes, restoration, or access to the billing portal, on organizations they are a member of but lack specific billing management authorization for. This directly impacts the targeted organizations, potentially leading to financial losses due to unwarranted subscription changes or cancellations. Furthermore, accessing another organization's billing portal exposes sensitive financial data, such as payment methods, invoices, and subscription states, to the unauthorized user. The scope of impact is limited to organizations that the attacker's user account is a member of.

## Recommendation

* Upgrade to `@better-auth/stripe@1.6.21` or later (for stable versions) or `@better-auth/stripe@1.7.0-beta.10` or later (for beta versions) to patch the vulnerability.
* If immediate upgrade is not possible, implement the recommended workaround by modifying the `authorizeReference` callback to ensure the `referenceId` matches `session.activeOrganizationId`, returning `false` otherwise.
* Configure web server logs to capture full HTTP request details, including query strings and request bodies, to aid in forensic analysis of suspicious activity.
* Review application-specific logs for instances where the `authorizeReference` callback approves an organization ID that differs from the `session.activeOrganizationId` during subscription actions, indicating a potential exploit attempt.
