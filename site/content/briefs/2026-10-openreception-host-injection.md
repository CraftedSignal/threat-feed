---
brief_id: brief-2026-10-23-openreception-host-injection
event_id: brief-2026-10-23-openreception-host-injection
revision: 1
activity_at: "2026-10-23T22:05:14Z"
title: 'OpenReception: Host header injection account takeover (CVE-2026-58202)'
slug: 2026-10-openreception-host-injection
description: OpenReception appointment booking software prior to version 2.0.0 is vulnerable to host header injection in the confirmation email generation process, allowing unauthenticated attackers to hijack user accounts.
date: "2026-10-23T22:05:14Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
cpes:
  - cpe:2.3:a:openreception:appointment_booking_software:*:*:*:*:*:*:*:*
vendors:
  - OpenReception
products:
  - appointment booking software (< 2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: 'An attacker who sends one resend-confirmation with Host: attacker.example and a pending invitee''s email causes that invitee to receive a confirmation email whose only link points to the attacker.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    subtechnique_id: T1136.001
    subtechnique_name: Local Account
    evidence: The attacker, who then confirms the account on the real tenant domain and registers a passkey they control, taking over the account.
    confidence_band: high
cves:
  - id: CVE-2026-58202
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58202
rules:
  - title: Detect CVE-2026-58202 Exploitation - Host Header Injection
    description: Detects exploitation attempts against the /api/auth/resend-confirmation endpoint by monitoring for Host headers that do not match expected internal tenant domains.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1566.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all OpenReception instances to version 2.0.0 or later.
      owner: IT Operations
      due: 24h
      evidence: This issue has been patched in version 2.0.0.
  hunt_leads:
    - lead: Search web server access logs for POST requests to /api/auth/resend-confirmation where the Host header does not match known tenant domains.
      technique_id: T1566.002
      data_needed:
        - cs-host
        - cs-uri-stem
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The unauthenticated POST /api/auth/resend-confirmation rotates a pending invitee's confirmation token and emails a link whose host comes from the request.
  mitigation_plan:
    - priority: immediate
      action: Configure the front-end proxy (e.g., Caddy, Nginx) to enforce explicit tenant domains and block requests with unrecognized Host headers.
      owner: IT Operations
      addresses: CVE-2026-58202
      evidence: 'Reaching the app with a spoofed Host depends on the front proxy: the stock Caddy catch-all forwards it, while an operator who configures explicit per-tenant proxy blocks is not affected.'
---

OpenReception versions prior to 2.0.0 contain a vulnerability in the '/api/auth/resend-confirmation' endpoint where the Host header is used to construct account confirmation links without validation or allowlisting. An unauthenticated attacker can force the system to send an email to a victim containing a link directed to an attacker-controlled domain. When the victim clicks the link, the one-time confirmation token is exposed, enabling the attacker to finalize the account registration and attach an attacker-controlled passkey.

## Attack Chain
1. Attacker identifies a target user's email address associated with a pending invite.
2. Attacker sends a POST request to '/api/auth/resend-confirmation'.
3. Attacker injects a malicious hostname into the 'Host' header of the request.
4. Application generates a confirmation email containing a link using the malicious host.
5. Victim receives the confirmation email and clicks the malicious link.
6. Attacker captures the one-time confirmation token from the request logs at their server.
7. Attacker uses the token to confirm the account on the legitimate tenant domain.
8. Attacker registers a passkey and completes the account takeover.

## Impact
Successful exploitation results in full account takeover, allowing attackers to access private booking data and assume the identity of the victim user within the platform.

## Recommendation
- Upgrade OpenReception to version 2.0.0 or later immediately.
- Implement strict Host header validation or explicit per-tenant proxy configurations in front-end proxies (e.g., Caddy, Nginx) to ensure requests only match authorized tenant domains.
- Audit logs for the '/api/auth/resend-confirmation' endpoint to identify requests containing unrecognized or anomalous 'Host' headers.
