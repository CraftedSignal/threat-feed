---
title: Broken Access Control in TinaCMS Authorization
slug: 2026-09-tinacms-auth-bypass
description: A broken access control vulnerability in @tinacms/auth allows attackers to perform unauthorized actions by supplying their own valid TinaCloud credentials against a victim's TinaCMS deployment.
date: "2026-09-17T19:14:33Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - TinaCMS
products:
  - '@tinacms/auth'
  - next-tinacms-cloudinary
  - next-tinacms-azure
  - next-tinacms-dos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker with a free TinaCloud account reaches editor-level control of unrelated tenants.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The victim's authorized callback returns true, and the victim authorizes the attacker.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g74q-6g2f-874x
iocs:
  - type: domain
    value: identity.tinajs.io
ioc_counts:
  domain: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review all self-hosted TinaCMS deployments for hard-coded clientID validation.
      owner: SOC
      due: 24h
      evidence: Source explicitly details the lack of clientID pinning in isAuthorized logic.
  enrichment_needed:
    - item: Affected deployment inventory.
      owner: CTI
      reason: Identify which internal sites are vulnerable.
      evidence: Exploit requires a self-hosted TinaCMS site.
  hunt_leads:
    - lead: Search logs for requests to /api/tina/gql or /api/cloudinary/media where clientID parameter is present.
      technique_id: T1190
      data_needed:
        - Webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The attack vector relies on passing a controlled clientID to these endpoints.
  mitigation_plan:
    - priority: immediate
      action: Pin clientID in the authorized callback to the site-specific value.
      owner: IT Operations
      addresses: Broken Access Control in TinaCMS
      evidence: Vulnerability stems from caller-controlled clientID.
  gaps:
    - Need visibility into GraphQL query parameters in web logs.
---

The `@tinacms/auth` package contains a critical broken access control vulnerability (confirmed at commit 5a6839f) that permits unauthorized cross-tenant access. The `isAuthorized(req)` function performs authorization by validating a bearer token against an identity provider endpoint (`https://identity.tinajs.io/v2/apps/${req.query.clientID}/currentUser`). Crucially, the function retrieves the `clientID` from the user-provided request parameters rather than comparing it against the site's locally configured TinaCloud application ID. 

An attacker with a standard TinaCloud account can exploit this by creating their own application, obtaining a valid token, and submitting requests to a victim site with their own `clientID` and token. The victim's application incorrectly validates the credentials against the attacker's own app, returning an authorized response. This vulnerability exposes critical functionality, including media bucket management and full GraphQL content read/write/delete capabilities when using the default `TinaCloudBackendAuthProvider`. The flaw exists across multiple integration libraries, including `next-tinacms-cloudinary`, `next-tinacms-azure`, and `next-tinacms-dos`.

## Attack Chain

1. Attacker registers a free TinaCloud account and creates a personal application to obtain a valid `clientID` and bearer token.
2. Attacker identifies a target self-hosted TinaCMS site that utilizes the vulnerable `@tinacms/auth` package or its derived media-store integrations.
3. Attacker crafts a malicious HTTP request (e.g., `GET /api/cloudinary/media`) targeting the victim's API endpoint.
4. Attacker includes their own `clientID` as a query parameter and their own valid TinaCloud bearer token in the `Authorization` header.
5. The victim's backend calls `isAuthorized(req)`, which incorrectly performs a look-up at `identity.tinajs.io` using the attacker-supplied `clientID`.
6. The identity provider returns a successful validation status because the credentials are valid for the attacker's own app.
7. The victim's backend logic, failing to pin the `clientID` to the site-specific ID, returns an `authorized: true` response to the media or GraphQL handler.
8. The attacker performs unauthorized actions, such as reading private media, uploading arbitrary files to the victim's CDN, or deleting/modifying site content.

## Impact

Successful exploitation allows an unauthenticated attacker to gain editor-level control over unrelated TinaCMS tenants. Impacts include the ability to list, read, or delete sensitive files within the victim's media bucket. Furthermore, when `TinaCloudBackendAuthProvider` is active, the attacker gains full GraphQL access, enabling the exfiltration of site content or the injection of malicious data into the CMS.

## Recommendation

1. Immediately audit all instances of `@tinacms/auth` and associated media/backend providers in self-hosted TinaCMS deployments.
2. Implement strict server-side validation to ensure the `clientID` provided in incoming requests matches the hard-coded or environment-configured application ID for that specific site.
3. Avoid relying solely on the return value of `isAuthorized(req)` without verifying that the returned `user` object's associated `appId` matches the expected deployment identifier.
4. Block or monitor suspicious inbound requests to `/api/cloudinary/media` or `/api/tina/gql` where the `clientID` parameter does not match your organization's known TinaCloud `clientID`.
