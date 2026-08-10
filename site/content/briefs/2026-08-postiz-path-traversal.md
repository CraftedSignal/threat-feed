---
title: Critical Path Traversal in Postiz Exploited for Instance Takeover
slug: 2026-08-postiz-path-traversal
description: An unauthenticated path traversal vulnerability (CVE-2026-19264) in Postiz enables remote attackers to read sensitive configuration files, facilitate JWT secret theft, and achieve full instance takeover through forged administrative sessions.
date: "2026-08-10T10:30:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - instance-takeover
  - cve-2026-19264
vendors:
  - Gitroom
products:
  - Postiz
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated path traversal in Postiz enables instance takeover via unchecked upload.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552.003
    technique_name: 'Unsecured Credentials: Credentials in Files'
    evidence: 'The Node process''s own configuration is on disk in the deployment root. .env yields, among other things: JWT_SECRET.'
    confidence_band: high
cves:
  - id: CVE-2026-19264
    cvss: 9.8
    epss: 0.00631
references:
  - https://vulners.com/cve/CVE-2026-19264
  - https://github.com/gitroomhq/postiz-app/security/advisories/GHSA-4hgh-5rhf-4qpm
  - https://gadvisory.org/advisories/PSA-2026-TH12B7
rules:
  - title: Detect CVE-2026-19264 Exploitation - Path Traversal via Upload Endpoint
    description: Detects exploitation attempts against Postiz by monitoring for percent-encoded path traversal sequences in requests to the uploads endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all Postiz instances to v2.22.1
      owner: IT Operations
      due: 24h
      evidence: Patched release v2.22.1 addresses CVE-2026-19264
    - action: Rotate JWT_SECRET and DATABASE_URL credentials
      owner: IT Operations
      due: 24h
      evidence: Rotation is required to invalidate any tokens forged prior to the patch
  hunt_leads:
    - lead: Search web logs for GET /uploads/ requests containing %2e or %2f
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker observed using these patterns to bypass routing
  mitigation_plan:
    - priority: immediate
      action: Upgrade Postiz to v2.22.1
      owner: IT Operations
      addresses: CVE-2026-19264
      evidence: The fix at commit 7936062 prevents the traversal
---

CVE-2026-19264 is a critical path traversal vulnerability discovered in Postiz, an open-source social media management tool. The vulnerability originates from improper path sanitization in the application's file upload/retrieval mechanism. Due to a decoding-order mismatch between the Next.js routing layer and the application handler, attackers can use percent-encoded traversal sequences (such as %2e%2e%2f) to bypass route-level security controls. This allows unauthorized access to arbitrary files on the host filesystem.

By reading the server's `.env` configuration file, an unauthenticated attacker can obtain the `JWT_SECRET` used for session signing and the `DATABASE_URL`. Because session tokens in affected versions of Postiz lack expiration claims, the recovered secret allows for the forging of administrative tokens, providing the attacker with permanent and elevated access to the instance. This vulnerability affects Postiz installations using the `local` storage provider, which is the default configuration.

## Attack Chain

1. The attacker probes the application to identify the `/uploads/` endpoint, which is used for file retrieval.
2. The attacker crafts an HTTP GET request containing percent-encoded path traversal sequences (e.g., `GET /uploads/..%2f..%2f..%2f.env`).
3. The Next.js routing layer fails to filter the encoded sequences because it does not recognize them as directory separators, allowing the request to reach the application handler.
4. The application handler decodes the percent-encoded sequences into literal `../` segments, which are then concatenated with the `UPLOAD_DIRECTORY` path.
5. The application performs a file read via `createReadStream()` on the resulting path, successfully resolving to sensitive files outside the intended upload directory.
6. The attacker reads the contents of the `.env` file from the returned HTTP response body, extracting the `JWT_SECRET` and `DATABASE_URL`.
7. Using the `JWT_SECRET`, the attacker signs a forged administrative session token.
8. The attacker authenticates to the application using the forged token, achieving full instance takeover and administrative control over the platform.

## Impact

Successful exploitation results in total system compromise. An attacker gains the ability to read any file readable by the application process, leading to the exfiltration of database credentials, OAuth secrets, and session signing keys. By forging session tokens, the attacker can impersonate any user, including administrators, without requiring prior authentication or user interaction. This vulnerability was verified as exploited in proof-of-concept form with a CVSS 3.1 score of 9.8.

## Recommendation

Prioritize the following actions to secure vulnerable Postiz environments:

* Immediately upgrade Postiz instances to version 2.22.1 or later to remediate the path traversal vulnerability.
* Treat the `JWT_SECRET` as compromised on all affected versions; rotate this secret immediately to invalidate existing forged sessions.
* Rotate `DATABASE_URL` credentials and any linked OAuth provider keys that were exposed via the environment file.
* Implement the following detection logic to monitor for ongoing exploitation attempts targeting the file retrieval path.
