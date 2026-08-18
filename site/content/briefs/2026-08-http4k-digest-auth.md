---
title: Authentication Bypass in http4k-security-digest via Digest URI Replay
slug: 2026-08-http4k-digest-auth
description: The http4k-security-digest library fails to validate the URI parameter in Digest authentication responses, enabling attackers to replay captured authentication credentials against unauthorized endpoints within the same realm.
date: "2026-08-18T00:46:37Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - http4k
products:
  - http4k-security-digest
references:
  - https://github.com/advisories/GHSA-p28p-j94q-pg32
  - https://datatracker.ietf.org/doc/html/rfc7616
  - https://github.com/http4k/http4k/commit/725f1b9697
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade http4k-security-digest to version 6.50.0.0, 5.42.0.0, or 4.51.0.0
      owner: IT Operations
      due: 48h
      evidence: Vendor patch availability in GHSA advisory
  mitigation_plan:
    - priority: immediate
      action: Configure reverse proxy to pin Digest-protected routes to specific URLs
      owner: IT Operations
      addresses: CVE-2026-54148
      evidence: Workaround documentation provided in source
---

The http4k-security-digest library, a component of the http4k framework, contains a vulnerability (CVE-2026-54148) that compromises the integrity of HTTP Digest authentication. The `DigestAuthProvider` component fails to verify that the `uri` parameter provided within an `Authorization: Digest` header matches the actual request URL. Because this binding is missing, an attacker who captures a valid Digest authentication response can successfully replay that credential to authenticate against any other resource protected by the same security realm. This flaw undermines the core security design of the Digest authentication scheme as described in RFC 7616. The vulnerability has been present in the codebase since commit 8a52b615b1, introduced in 2021. Impacted users should upgrade to the corrected versions (6.50.0.0, 5.42.0.0, or 4.51.0.0) or implement compensatory controls such as reverse proxy URL pinning.

## Attack Chain

1. Attacker observes legitimate Digest-protected traffic between a client and the target server.
2. Attacker performs a Man-in-the-Middle (MitM) or passive interception to capture the `Authorization: Digest` header.
3. Attacker identifies a different, unauthorized URL served by the same http4k-security-digest realm.
4. Attacker constructs an HTTP request targeting the unauthorized resource.
5. Attacker includes the previously captured `Authorization: Digest` header in the request to the new endpoint.
6. The `DigestAuthProvider` component processes the request and incorrectly validates the credentials because it ignores the `uri` mismatch.
7. Server grants access to the unauthorized resource, completing the authentication bypass.

## Impact

Successful exploitation allows for the unauthorized access of any resource protected by the Digest authentication scheme within the vulnerable application realm. This vulnerability affects any deployment utilizing `http4k-security-digest` for authentication. The potential damage includes unauthorized data access, privilege escalation, and lateral movement within the application, depending on the sensitivity of the endpoints protected by the affected authentication provider.

## Recommendation

* Upgrade to the patched versions of http4k-security-digest immediately: 6.50.0.0 (Community), 5.42.0.0 (LTS), or 4.51.0.0 (LTS).
* If an immediate upgrade is not possible, place the affected Digest authentication endpoints behind a reverse proxy that enforces strict URI binding and pins requests to a single intended URL.
* Audit application logs for patterns of the same `Authorization: Digest` header being reused across different `cs-uri-stem` paths to identify potential exploitation attempts.
