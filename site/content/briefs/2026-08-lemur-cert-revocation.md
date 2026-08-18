---
title: Authorization Bypass in Lemur Leading to Unauthorized Certificate Revocation
slug: 2026-08-lemur-cert-revocation
description: An authorization bypass vulnerability in Lemur allows authenticated users to revoke arbitrary certificates by creating duplicate certificate records and bypassing ownership and endpoint-attached safeguards.
date: "2026-08-18T20:56:29Z"
lastmod: "2026-08-18T20:56:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - certificate-management
  - authorization-bypass
  - cve-2026-71417
  - cloud
vendors:
  - Netflix
products:
  - lemur
  - Lemur (>= 0.5.0, <= 1.9.2)
  - Lemur (<= 1.9.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Iterating over GET /certificates yields fleet-wide revocation (mass DoS of TLS endpoints).
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The attacker exploits the application logic to manipulate backend tasks to perform unauthorized actions on infrastructure.
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The built-in SFTP destination plugin (sftp-destination) stores its password and privateKeyPass options in cleartext in the destinations.options column.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The update endpoint accepts and stores arbitrary options, including a modified acme_url, without invoking the allowlist check.
    confidence_band: high
cves:
  - id: CVE-2026-71417
    cvss: 7.3
references:
  - https://github.com/advisories/GHSA-pxmc-2ffp-8j67
  - https://github.com/Netflix/lemur
  - https://github.com/advisories/GHSA-cfh6-pv5c-38jv
  - https://github.com/Netflix/lemur/blob/master/lemur/certificates/schemas.py
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71308
  - https://github.com/advisories/GHSA-6c8m-q6g9-vrw3
  - https://github.com/advisories/GHSA-v5rc-cpwc-cfpr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71303
rules:
  - title: Detect Exploitation of CVE-2026-71303 - SSRF via Lemur Authority Update
    description: Detects PUT requests to the Lemur authority update API that contain potential SSRF targets in the acme_url option
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1505
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Lemur to a non-vulnerable version.
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends update to patch CVE-2026-71417.
updates:
  - at: "2026-08-18T20:56:38Z"
    level: L2
    summary: added coverage for Lemur (>= 0.5.0, <= 1.9.2)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-cfh6-pv5c-38jv
  - at: "2026-08-18T20:56:45Z"
    level: L2
    summary: added coverage for Lemur
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-6c8m-q6g9-vrw3
  - at: "2026-08-18T20:56:54Z"
    level: L2
    summary: 'added detection rule: Detect Exploitation of CVE-2026-71303 - SSRF via Lemur Authority Update'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-v5rc-cpwc-cfpr
---

Lemur (<= 1.9.2) contains a critical authorization bypass vulnerability, identified as CVE-2026-71417, which permits any authenticated user with non-read-only permissions to revoke production certificates. The vulnerability stems from an insecure certificate upload workflow that allows users to supply external identifiers (like `body` or `external_id`) without validating `AuthorityPermission`. 

Because the Lemur database lacks uniqueness constraints on these identifiers, an attacker can create a duplicate certificate record for a target production certificate. When the attacker initiates a revocation on this newly created, attacker-owned duplicate, the application's authorization logic bypasses the ownership check. Furthermore, because the duplicate record has no associated endpoints in the Lemur database, the safety mechanism designed to prevent the revocation of active production certificates is entirely bypassed. This allows an attacker to interact with the issuing CA using the CA's stored credentials to revoke legitimate, live certificates, facilitating mass denial-of-service (DoS) of TLS-protected infrastructure.

## Attack Chain

1. The attacker queries the API (e.g., `GET /api/1/certificates/<ID>`) to obtain the `body`, `authority.id`, and `external_id` of a target production certificate.
2. The attacker uses the `POST /api/1/certificates/upload` endpoint to create a new certificate record in the Lemur database.
3. The attacker provides the target's stolen metadata in the upload request; Lemur accepts this as a new record because it lacks uniqueness constraints on `body` or `external_id`.
4. The attacker is now the creator/owner of the new, duplicate database record, which satisfies the `g.current_user != cert.user` authorization check in `views.py`.
5. The attacker calls `PUT /api/1/certificates/<DUP_ID>/revoke` on the duplicate certificate record.
6. The system checks for existing endpoints associated with the record; since the duplicate record has none, the safety check is bypassed.
7. The Lemur issuer plugin retrieves the CA credentials and invokes the CA's revocation API using the `body` or `external_id` provided by the attacker.
8. The issuing CA processes the revocation, rendering the target production certificate invalid.

## Impact

Successful exploitation allows a low-privileged authenticated user to perform fleet-wide revocation of TLS certificates. This results in an immediate denial-of-service for all services using the revoked certificates. Given the ability to iterate through available certificate IDs via the API, the impact can extend to entire organizations, affecting both internal and external-facing TLS-secured endpoints.

## Recommendation

Prioritize patching the Lemur instance to a version containing the remediation for CVE-2026-71417. Detection teams should monitor for anomalous usage of the certificate upload and revocation endpoints.

- Upgrade the Lemur package to a version beyond 1.9.2 immediately.
- Implement a database-level uniqueness constraint on the `(authority_id, serial)` or `body` fields for certificate records to prevent duplicate aliasing.
- Audit access logs for users performing rapid sequences of certificate uploads followed by revocation calls.
- Restrict the `POST /api/1/certificates/upload` and `PUT /api/1/certificates/<ID>/revoke` endpoints to ensure that `AuthorityPermission` is validated regardless of row ownership.
