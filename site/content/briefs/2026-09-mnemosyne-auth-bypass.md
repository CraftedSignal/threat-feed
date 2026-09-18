---
title: Mnemosyne Sync Server Authentication Bypass via JWT Signature Verification Failure
slug: 2026-09-mnemosyne-auth-bypass
description: A flaw in the Mnemosyne sync server's JWT implementation fails to verify HMAC-SHA256 signatures, allowing unauthenticated attackers to forge tokens and access or modify arbitrary user data.
date: "2026-09-18T19:46:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
cves:
  - id: CVE-2026-59163
    cvss: 9.1
---

The Mnemosyne sync server (up to v3.10.0) contains a critical authentication bypass vulnerability (CVE-2026-59163) resulting from incomplete JWT verification logic. While the server parses and decodes incoming JWT bearer tokens, it fails to perform cryptographic signature validation. Consequently, the server accepts any well-formed JWT token, regardless of the 'alg' header value or the integrity of the signature. An unauthenticated attacker can forge tokens containing arbitrary user IDs to gain unauthorized access to the sync service. This impact includes the ability to read sync state, push malicious data that corrupts local databases, and impersonate any user on the platform. Defenders should prioritize patching to v3.10.1 or restricting network access to the sync endpoint immediately.

## Attack Chain

1. Attacker identifies a network-reachable Mnemosyne sync server endpoint.
2. Attacker crafts a malicious JWT header with 'alg: HS256' and a payload containing the target 'user_id'.
3. Attacker base64url-encodes the header and payload components.
