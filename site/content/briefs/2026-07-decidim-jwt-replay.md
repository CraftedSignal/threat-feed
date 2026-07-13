---
title: Decidim JWT Replay Vulnerability Allows Cross-Organization Data Access
slug: 2026-07-decidim-jwt-replay
description: A vulnerability, CVE-2026-45414, in Decidim allows an attacker to replay a JSON Web Token (JWT) issued for one organization against another organization's API, permitting an authenticated user from Org 1 to access and retrieve sensitive data, such as GraphQL `participantDetails` and `proposal.answer` mutation paths, from Org 2, effectively bypassing cross-organizational access controls.
date: "2026-07-13T17:19:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - jwt-misconfiguration
  - access-control
  - web-application
  - vulnerability
vendors:
  - Decidim
products:
  - Decidim (< 0.31.5)
  - Decidim (>= 0.32.0.rc1, < 0.32.0)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A JWT issued to an Org 1 account is accepted on the Org 2 API
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: can read the admin-only GraphQL `participantDetails` field for an Org 2 participant
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-r3v7-5x4c-c69q
  - https://github.com/decidim/decidim/pull/16673
  - https://github.com/decidim/decidim/pull/16756
---

A high-severity vulnerability, tracked as CVE-2026-45414, exists in the Decidim platform versions prior to 0.31.5 and in versions >= 0.32.0.rc1 but < 0.32.0. This flaw permits a malicious actor to perform a JWT replay attack, enabling unauthorized access to data across different Decidim organizational instances. An attacker, leveraging a valid JWT obtained from one organization (e.g., Org 1), can bypass access controls and access sensitive information or manipulate data within a separate, distinct organization (e.g., Org 2) by simply altering the HTTP Host header. This misconfiguration in how JWTs are bound to specific organizational contexts allows for the retrieval of admin-only GraphQL fields like `participantDetails` and interaction with mutation paths such as `proposal.answer`, posing a significant risk of data exposure and unauthorized modification across multi-tenant Decidim deployments.

## Attack Chain

1. An attacker first obtains a valid JWT associated with a legitimate account in Organization 1, either by using an API key provided by a system administrator or by capturing the JWT from an authenticated session of an Org 1 administrator.
2. The attacker identifies a target Decidim instance belonging to Organization 2, which is operating on the same vulnerable Decidim version.
3. The attacker crafts an HTTP request targeting a sensitive API endpoint of Organization 2, such as `/api/graphql`.
4. The attacker modifies the `Host` HTTP header in the crafted request to specify Organization 2's domain (e.g., `org2.localhost:3001`), deceiving the Org 2 API into processing the request within its context.
5. The attacker embeds the valid JWT obtained from Organization 1 into the `Authorization` header of the request.
6. The Organization 2 API, due to the JWT scope misconfiguration, accepts the Org 1 JWT as valid for its own context.
7. The attacker then uses this replayed JWT to retrieve sensitive data, such as admin-only GraphQL `participantDetails` for Org 2 participants.
8. The attacker may also access and potentially manipulate data through sensitive mutation paths like `proposal.answer` within Organization 2, leading to unauthorized data exposure and integrity compromise.

## Impact

The successful exploitation of CVE-2026-45414 leads to unauthorized cross-organizational data access and potential manipulation. Attackers can retrieve highly sensitive personal data of participants (e.g., via `participantDetails`) and interact with critical organizational processes (e.g., `proposal.answer` mutation path). While the number of specific victims or targeted sectors is not provided, any organization utilizing vulnerable Decidim versions in a multi-tenant or multi-organizational setup is at risk. If exploited, this could result in severe privacy breaches, unauthorized changes to proposals, and significant reputational damage for affected organizations, as sensitive administrative and user data from one organization could be exposed to an attacker authenticated to a different organization.

## Recommendation

* Patch Decidim instances immediately to version 0.31.5 or newer, or to 0.32.0 or newer if running release candidate versions, as described in the provided `https://github.com/decidim/decidim/pull/16673` and `https://github.com/decidim/decidim/pull/16756` references.
* If immediate patching is not possible, implement the workaround by disabling JWT credentials on the system panel (`/system`) of all Decidim instances.
* Review web server logs for suspicious requests to Decidim API endpoints that contain `Authorization: Bearer <JWT>` headers but have unusual or unexpected `Host` headers that do not match the legitimate domain of the application server.
