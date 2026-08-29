---
title: Omnivore API Authentication Bypass via JWT Algorithm Confusion
slug: 2026-08-omnivore-auth-bypass
description: The Omnivore API improperly validates Apple sign-in tokens, allowing attackers to perform algorithm confusion attacks to bypass authentication and impersonate users.
date: "2026-08-29T15:39:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:omnivore:omnivore_api:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - jwt-confusion
  - web-vulnerability
vendors:
  - Omnivore
products:
  - Omnivore API (< abf53d6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.001
    technique_name: Use Alternate Authentication Material
    evidence: An attacker can set alg=HS256 and sign a forged token using Apple's publicly available RSA public key as the HMAC secret, bypassing signature verification and impersonating any Apple-linked account.
    confidence_band: high
cves:
  - id: CVE-2026-82454
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82454
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Omnivore API to commit abf53d6 or later.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies commit abf53d6 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Omnivore API to commit abf53d6 or later.
      owner: IT Operations
      addresses: CVE-2026-82454
      evidence: NVD vulnerability disclosure
---

The Omnivore API, specifically within the packages/api module, contains a critical authentication bypass vulnerability (CVE-2026-82454) arising from insecure JSON Web Token (JWT) verification. The vulnerability exists within the decodeAppleToken function, which extracts the 'alg' header field from an attacker-supplied token and passes it directly to the verification function. Because the implementation uses an outdated version of the jsonwebtoken library (v8), it fails to enforce strict key and algorithm compatibility. An attacker can craft a forged JWT by setting the 'alg' field to 'HS256' and using the publicly available Apple RSA public key as the HMAC shared secret. This allows the attacker to successfully authenticate as any user registered via Apple Sign-in, potentially leading to full account takeover. The issue is resolved in commit abf53d6.

## Impact

Successful exploitation allows unauthenticated attackers to impersonate any user currently using the Apple sign-in method within the Omnivore ecosystem. This leads to complete unauthorized access to victim accounts, enabling the exfiltration of personal data, account settings modification, and further malicious activity. The vulnerability carries a CVSS v3.1 base score of 9.1, indicating a high risk to availability, integrity, and confidentiality of user accounts.

## Recommendation

1. Upgrade the Omnivore API deployment to a version incorporating the fix identified in commit abf53d6 or later.
2. Perform an audit of application authentication logs for anomalous Apple Sign-in traffic, specifically looking for tokens where the header 'alg' field does not match the expected 'RS256' algorithm.
3. Validate if the environment is utilizing vulnerable versions of the jsonwebtoken library and update to a version that enforces strict algorithm-to-key matching (e.g., jsonwebtoken v9 or newer).
