---
title: zot Registry Unauthorized Deletion via Bearer Token Scope Mismatch
slug: 2026-09-zot-unauthorized-deletion
description: A logic flaw in zot registry's bearer authentication handler causes HTTP DELETE requests to be incorrectly mapped to the 'push' scope, allowing unauthorized deletion of image manifests and blobs by push-only clients.
date: "2026-09-18T19:51:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-61833
    cvss: 8.1
---

The zot container registry (versions prior to 2.1.18) contains a security vulnerability (CVE-2026-61833) in its bearer authentication implementation. The registry incorrectly collapses all non-GET/HEAD HTTP methods - including DELETE - into the "push" scope action. Furthermore, the `DistSpecAuthzHandler` middleware, which is designed to enforce granular action authorization, is explicitly bypassed for requests authenticated via bearer tokens. 

As a result, any client holding a bearer token with only "push" permissions can successfully execute DELETE operations on manifests and blobs within the repository scope. This behavior violates the Docker Distribution Token Authentication Specification, which mandates that "delete" be treated as a distinct, privileged action. This flaw poses a significant risk to CI/CD pipelines where service tokens are intentionally scoped to prevent unauthorized modification or deletion of registry assets. An attacker with access to a push-only token can render container images unpullable or disrupt service availability by deleting critical image layers.

## Attack Chain

1. Attacker gains access to a bearer token scoped for `pull` and `push` actions (e.g., via compromised CI/CD pipeline credentials).
2. Attacker crafts an HTTP DELETE request targeting a specific image manifest or blob within the repository scope of the stolen token.
3. The request is sent to the zot registry server with the `Authorization: Bearer <TOKEN>` header.
4. The zot bearer authentication handler processes the request and maps the DELETE method to the "push" action due to the flawed logic in `pkg/api/authn.go`.
5. The `DistSpecAuthzHandler` middleware identifies the request as bearer-authenticated and initiates an early exit, bypassing granular permission verification for the "delete" action.
6. The `DeleteManifest` or `DeleteBlob` route handler receives the request and executes the deletion process
