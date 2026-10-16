---
title: Authentication Bypass in bbs-go via Improper OAuth Token Validation
slug: 2026-10-bbs-go-auth-bypass
description: The bbs-go application up to version 4.4.6 is vulnerable to an authentication bypass via the /api/login/google_one_tap endpoint due to missing validation of the Google ID token audience claim.
date: "2026-10-16T18:47:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bbs-go:bbs-go:*:*:*:*:*:*:*:*
products:
  - bbs-go (<= 4.4.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The application fails to validate the 'aud' claim in Google ID tokens, allowing remote attackers to log in as other users.
    confidence_band: high
cves:
  - id: CVE-2026-111639
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111639
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Monitor /api/login/google_one_tap for excessive login attempts or unusual origin patterns.
      owner: SOC
      due: 24h
      evidence: Endpoint identified in CVE-2026-111639.
  mitigation_plan:
    - priority: immediate
      action: Upgrade bbs-go to the latest secure version once released by the maintainer.
      owner: IT Operations
      addresses: CVE-2026-111639
      evidence: NVD advisory.
---

The bbs-go application, in versions through 4.4.6, contains a critical authentication bypass vulnerability identified as CVE-2026-111639. The vulnerability exists within the /api/login/google_one_tap endpoint, which handles Google One Tap authentication. The application fails to verify the 'aud' (audience) claim within the Google-issued ID token provided during the authentication flow.

By default, Google ID tokens are scoped to the specific OAuth client ID that requested them. Because bbs-go neglects to validate that the 'aud' claim matches its own registered client ID, an attacker can create their own Google OAuth client and obtain an ID token. An attacker can then replay a victim's Google ID token - or use a token issued to the attacker's own client - to successfully authenticate as the victim's Google-linked account. This flaw allows for full account takeover of any user associated with a Google identity, posing a significant risk to user confidentiality and account integrity.

## Impact

Successful exploitation of this vulnerability results in unauthorized access to user accounts. An attacker can impersonate any user who has linked a Google account to their bbs-go profile, gaining full access to the victim's data and account privileges. This vulnerability impacts all installations of bbs-go version 4.4.6 and earlier.

## Recommendation

1. Upgrade bbs-go to a patched version once available that implements strict validation of the 'aud' claim in Google ID tokens.
2. Implement monitoring on web access logs for the /api/login/google_one_tap endpoint to identify anomalies in successful login rates or unexpected 'aud' claims if logging allows inspection of the token payload.
3. Review audit logs for suspicious account modifications or unauthorized access patterns if the application logs identity provider information.
