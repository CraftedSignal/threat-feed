---
title: SigV4 Authentication Bypass in rclone serve s3
slug: 2026-09-rclone-auth-bypass
description: A critical authentication bypass vulnerability in rclone's S3 serving mode allows unauthenticated attackers to spoof identity via forged SigV4 signatures when '--auth-proxy' is used without '--auth-key'.
date: "2026-09-11T00:53:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:rclone:rclone:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - s3
  - rclone
  - cve-2026-88018
vendors:
  - rclone
products:
  - rclone (< 1.75.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: An attacker can trivially compute a correct SigV4 signature for ANY access key ID of their choosing using an empty secret, and verification passes.
    confidence_band: high
cves:
  - id: CVE-2026-88018
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-xwwr-4h3p-r22c
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88018
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade rclone to 1.75.1 on all servers running 'serve s3' with '--auth-proxy'
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-88018 fix is available in 1.75.1
  mitigation_plan:
    - priority: immediate
      action: Remove or reconfigure 'serve s3 --auth-proxy' instances lacking '--auth-key'
      owner: IT Operations
      addresses: CVE-2026-88018
      evidence: Documentation states the vulnerability exists when --auth-key is missing
---

The rclone `serve s3` command contains a critical vulnerability (CVE-2026-88018) in its authentication middleware chain. When a user configures `rclone serve s3` with the `--auth-proxy` flag but fails to provide an `--auth-key`, the application incorrectly handles the credential registration process. Specifically, the `authPairMiddleware` parses the `AccessKeyID` directly from the client-controlled `Authorization` header and registers it into the internal credential store with an empty string as the secret key.

Because an empty string is a valid HMAC key for SigV4, any network-reachable attacker can compute a valid signature for an arbitrary `AccessKeyID` using an empty secret. The application subsequently accepts these forged signatures as authenticated requests. This effectively bypasses all authentication for the S3 interface, granting attackers the ability to interact with the backend as any identity accepted by the configured auth-proxy script. This vulnerability affects all rclone versions prior to 1.75.1.

## Attack Chain

1. Attacker identifies a network-accessible rclone instance running `serve s3` with `--auth-proxy` enabled.
2. Attacker verifies the configuration lacks an `--auth-key` (often inferred by testing unauthorized access).
3. Attacker selects an arbitrary `AccessKeyID` to impersonate a target user or administrative account.
4. Attacker constructs an S3 API request (e.g., `ListAllMyBuckets`) using the chosen `AccessKeyID`.
5. Attacker computes a valid SigV4 signature for the request payload using an empty string as the secret key.
6. Attacker sends the forged request to the rclone instance.
7. The `authPairMiddleware` registers the attacker-supplied key with an empty secret in the internal store.
8. The gofakes3 handler validates the forged signature against the registered empty secret, granting full access to the requested S3 backend.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain full access to the S3 interface of an rclone instance. This can lead to unauthorized data exfiltration, deletion, or modification of stored objects, depending on the permissions of the identities handled by the auth-proxy script. No prior credentials or user interaction are required for exploitation.

## Recommendation

* Upgrade rclone to version 1.75.1 or later immediately to apply the fix that prevents the server from starting with an insecure configuration.
* Audit existing rclone deployments for the usage of `--auth-proxy` in `serve s3` commands.
* Ensure that all `serve s3` instances utilizing `--auth-proxy` are configured with a robust `--auth-key` if immediate upgrading is not feasible, although upgrading is the only supported mitigation.
* Review logs for S3 requests that appear to be authenticated using anomalous or unknown `AccessKeyID` values.
