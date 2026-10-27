---
brief_id: brief-2026-10-27-kener-auth-bypass
event_id: brief-2026-10-27-kener-auth-bypass
revision: 1
activity_at: "2026-10-27T01:51:46Z"
title: 'Kener: Authentication bypass via hardcoded secret (CVE-2026-116747)'
slug: 2026-10-kener-auth-bypass
description: Kener versions 3.0.0 through 4.1.9 contain an authentication bypass vulnerability allowing attackers to forge administrative session tokens using a hardcoded fallback secret.
date: "2026-10-27T01:51:46Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:kener:kener:*:*:*:*:*:*:*:*
vendors:
  - Kener
products:
  - Kener (< 4.1.10)
cves:
  - id: CVE-2026-116747
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116747
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Kener to version 4.1.10 or later
      owner: IT Operations
      due: 24h
      evidence: Kener 3.0.0 before 4.1.10 contains an authentication bypass vulnerability
  hunt_leads:
    - lead: Identify administrative access attempts to /manage/api from unauthorized or suspicious client sources
      technique_id: T1550.002
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers... can sign a kener-user cookie to access /manage/api with full administrative privileges
  mitigation_plan:
    - priority: immediate
      action: Configure KENER_SECRET_KEY environment variable with a strong secret
      owner: IT Operations
      addresses: CVE-2026-116747
      evidence: When KENER_SECRET_KEY is empty or unset, attackers knowing an administrator email can sign a kener-user cookie
---

Kener versions 3.0.0 through 4.1.9 are susceptible to an authentication bypass vulnerability. If the 'KENER_SECRET_KEY' environment variable is not explicitly set, the application defaults to a hardcoded 'DUMMY_SECRET' fallback key. An unauthenticated attacker aware of an administrator's email address can use this key to sign 'kener-user' cookies, granting them administrative access to '/manage/api' or enabling the generation of unauthorized password-reset tokens.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative privileges and perform sensitive actions within the Kener management API or hijack account authentication flows.

## Recommendation

- Upgrade Kener to version 4.1.10 or later immediately.
- If upgrading is not immediately possible, ensure the 'KENER_SECRET_KEY' environment variable is explicitly configured with a cryptographically secure, high-entropy string to prevent the application from falling back to the hardcoded default.
- Audit logs for the '/manage/api' endpoint for successful requests originating from unexpected IP addresses or associated with suspected forged cookies.
