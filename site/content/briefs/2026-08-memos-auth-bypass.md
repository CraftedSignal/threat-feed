---
title: Authentication Bypass in MemOS via Internal Middleware Misconfiguration
slug: 2026-08-memos-auth-bypass
description: MemOS contains an authentication bypass vulnerability where unset environment variables cause the internal request middleware to fail open, granting unauthenticated remote attackers administrative access.
date: "2026-08-17T22:51:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - MemOS
products:
  - MemOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can reach the admin API-key management endpoints.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'The request is then treated as a trusted internal principal and granted scopes: ["all"].'
    confidence_band: high
cves:
  - id: CVE-2026-75110
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75110
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Set INTERNAL_SERVICE_SECRET environment variable on all MemOS instances
      owner: IT Operations
      due: 24h
      evidence: Unset variable causes logic bypass.
---

MemOS, a memory operating system designed for LLMs and AI agents, contains a critical authentication bypass vulnerability (CVE-2026-75110). The issue resides in the `is_internal_request()` function within `src/memos/api/middleware/auth.py`. In environments where `AUTH_ENABLED` is set to `true`, the system attempts to verify internal service requests by comparing the `X-Internal-Service` header against the `INTERNAL_SERVICE_SECRET` environment variable. 

If the `INTERNAL_SERVICE_SECRET` variable is not explicitly configured by the administrator, the `os.getenv` call returns `None`. Simultaneously, a request lacking the `X-Internal-Service` header also results in `None`. Consequently, the comparison `None == None` evaluates to `true`, causing the middleware to improperly classify an unauthenticated external request as a trusted internal principal with "all" scopes. This flaw grants attackers full access to sensitive administrative endpoints, including those for API-key management, allowing them to mint, enumerate, and revoke keys, or generate a master key for persistent, privileged unauthorized access to the entire data platform.

## Attack Chain

1. Attacker performs reconnaissance to identify a MemOS deployment exposing the API surface.
2. Attacker probes the authentication middleware by sending arbitrary requests without the `X-Internal-Service` header.
3. The server-side `auth.py` middleware retrieves the value of the unset `INTERNAL_SERVICE_SECRET` environment variable, which resolves to `None`.
4. The middleware retrieves the missing header value from the request, which also resolves to `None`.
5. The `is_internal_request()` function executes the comparison `None == None`, returning `True`.
6. The MemOS middleware grants the request a trusted internal principal identity with broad "all" scopes.
7. Attacker submits requests to the `/api/key-management` endpoint to mint new administrative API keys.
8. Attacker uses the newly minted keys to exfiltrate data or gain persistent, unauthorized administrative access.

## Impact

Successful exploitation of this vulnerability leads to complete compromise of the MemOS instance. An attacker can bypass all authentication controls, gain administrative access to API-key management, and exfiltrate or manipulate LLM/agent memory data. Given the "all" scope granted, attackers can generate persistent master keys, effectively providing long-term unauthorized access even if the underlying environment configuration is eventually corrected.

## Recommendation

Prioritize the immediate remediation of affected MemOS instances.

- Deploy an `INTERNAL_SERVICE_SECRET` environment variable with a strong, high-entropy secret key immediately to force the `os.getenv` return value to be non-null.
- Review all logs for unauthorized access to administrative paths (e.g., `/api/key-management`) originating from external IP addresses.
- Audit all active API keys in the MemOS deployment for unauthorized additions or modifications created since the deployment was initialized.
- Upgrade MemOS to the patched version once released by the vendor to enforce robust header validation.
