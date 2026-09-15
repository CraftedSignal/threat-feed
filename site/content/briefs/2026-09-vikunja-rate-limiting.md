---
title: Unauthenticated Rate Limiting Vulnerability in Vikunja Authentication Endpoints
slug: 2026-09-vikunja-rate-limiting
description: Vikunja versions before 2.6.0 lack rate limiting on public /api/v2 authentication endpoints, enabling credential stuffing, account enumeration, and password-reset flooding.
date: "2026-09-15T17:44:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:vikunja:vikunja:*:*:*:*:*:*:*:*
vendors:
  - Vikunja
products:
  - Vikunja (< 2.6.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Remote unauthenticated attackers can perform unbounded credential guessing, account enumeration, and password-reset flooding attacks without throttling restrictions.
    confidence_band: high
cves:
  - id: CVE-2026-91972
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91972
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Vikunja to 2.6.0
      owner: IT Operations
      due: 48h
      evidence: Source advisory states versions before 2.6.0 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Configure WAF to limit request rates on /api/v2/ endpoints
      owner: SOC
      addresses: CVE-2026-91972
      evidence: Source notes lack of rate limiting on /api/v2 endpoints
---

Vikunja versions prior to 2.6.0 contain a critical vulnerability in the handling of public API requests. The platform fails to apply rate limiting or throttling mechanisms to key /api/v2 authentication endpoints, including those responsible for user login, registration, password resets, and OAuth token exchanges. This architectural oversight allows remote, unauthenticated attackers to perform unbounded high-volume requests against these services. The absence of defensive controls such as IP-based throttling or request rate limiting facilitates automated brute-force attacks, large-scale account enumeration, and denial-of-service scenarios via password-reset flooding. Given the exposure of these endpoints to the public internet, defenders should prioritize upgrading to version 2.6.0 or implementing external rate-limiting controls at the web application firewall (WAF) or reverse proxy level to mitigate potential exploitation.

## Impact

The vulnerability poses a significant risk to user account integrity and system availability. Success in exploiting this flaw enables attackers to compromise user accounts through credential stuffing, map user existence within the application through account enumeration, and disrupt user access by flooding the password-reset infrastructure. Organizations hosting Vikunja are susceptible to automated malicious traffic that can bypass basic security protections, potentially leading to widespread account takeovers.

## Recommendation

1. Upgrade all instances of Vikunja to version 2.6.0 or later immediately to apply the required rate-limiting patches.
2. Deploy WAF rules or reverse proxy rate-limiting configurations for the /api/v2 endpoint path to block high-frequency requests originating from single IP addresses or identified automated agents.
3. Monitor web server logs for anomalous spikes in POST requests to /api/v2/login, /api/v2/register, and /api/v2/password-reset.
