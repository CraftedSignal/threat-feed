---
title: FUXA Server Unauthenticated Tag Value Disclosure (CVE-2026-43946)
slug: 2026-05-fuxa-tag-disclosure
description: FUXA server 1.3.0 has an unauthenticated arbitrary tag value disclosure vulnerability (CVE-2026-43946); an authorization bypass in the /api/getTagValue endpoint allows unauthenticated access to tag values when the referenced script does not exist.
date: "2026-05-26T23:44:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - information-disclosure
  - cve
vendors:
  - npm
products:
  - fuxa-server (= 1.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Appliances
references:
  - https://github.com/advisories/GHSA-fwcm-rqvw-j3p7
  - CVE-2026-43946
rules:
  - title: Detect Unauthenticated FUXA Tag Value Access
    description: Detects CVE-2026-43946 — Unauthenticated access to FUXA's /api/getTagValue endpoint by monitoring requests lacking authorization headers
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
  - title: Detect FUXA Tag Value Access with Missing Script
    description: Detects CVE-2026-43946 — Attempts to access FUXA's /api/getTagValue endpoint with a non-existent sourceScriptName, indicating potential exploitation
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
rules_count: 2
---

FUXA server version 1.3.0 is vulnerable to an unauthenticated arbitrary tag value disclosure (CVE-2026-43946) via the `/api/getTagValue` endpoint. The vulnerability stems from an authorization bypass that occurs when a request is made to `/api/getTagValue` referencing a script that does not exist. This causes the `isAuthorisedByScriptName()` function to return `true` for the guest user, effectively bypassing authentication checks. An unauthenticated attacker can then retrieve arbitrary tag values by ID. This vulnerability allows unauthorized access to potentially sensitive information managed by the FUXA server.

## Attack Chain

1.  The attacker sends an unauthenticated HTTP request to the `/api/getTagValue` endpoint.
2.  The request lacks an `x-api-key` header, so `server/api/apikeys/verify-api-or-token.js` forwards the request to `authJwt.verifyToken(req, res, next)`.
3.  Since no `x-access-token` is provided, `server/api/jwt-helper.js` generates a signed guest token.
4.  `server/api/jwt-helper.js` populates `req.userId` and `req.userGroups` with data from the guest token.
5.  The request reaches `/api/command/index.js`, which handles requests to `/api/getTagValue`.
6.  The authorization check in `/api/command/index.js` calls `isAuthorisedByScriptName()`.
7.  `server/runtime/scripts/index.js` checks if the referenced script exists; if the script does not exist, `isAuthorisedByScriptName()` returns `true`.
8.  The authorization check is bypassed, and the attacker retrieves arbitrary tag values by ID.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to retrieve arbitrary tag values managed by the FUXA server. This could lead to the disclosure of sensitive information, depending on the nature of the data stored in the tags. The vulnerability affects FUXA server version 1.3.0.

## Recommendation

*   Monitor web server logs for requests to the `/api/getTagValue` endpoint without valid authentication headers, using the Sigma rule `Detect Unauthenticated FUXA Tag Value Access`.
*   Inspect web server logs for requests to `/api/getTagValue` with non-existent `sourceScriptName`, using the Sigma rule `Detect FUXA Tag Value Access with Missing Script`.
*   Upgrade FUXA server to a patched version that addresses CVE-2026-43946.
