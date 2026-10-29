---
brief_id: brief-2026-10-23-openreception-host-injection
event_id: brief-2026-10-23-openreception-host-injection
revision: 2
activity_at: "2026-10-29T20:03:29Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:03:29Z"
    checksum: sha256:898ea449a990f1b2348fb7167cce364a5a2713bfd1f935572fd6c3706a06960e
    summary: added coverage for appointment booking software (<= 2.1.0)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - qa_status
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-65825
title: 'OpenReception: Host header injection account takeover (CVE-2026-58202)'
slug: 2026-10-openreception-host-injection
description: OpenReception appointment booking software prior to version 2.0.0 is vulnerable to host header injection in the confirmation email generation process, allowing unauthenticated attackers to hijack user accounts.
date: "2026-10-23T22:05:14Z"
lastmod: "2026-10-29T20:01:11Z"
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
qa_status:
  verdict: pass
  validation_status: Source verified; patch available.
cpes:
  - cpe:2.3:a:openreception:appointment_booking_software:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - cve-2026-65825
vendors:
  - OpenReception
products:
  - appointment booking software (< 2.0.0)
  - appointment booking software (< 2.2.1)
  - appointment booking software (<= 2.1.0)
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
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: An attacker who captures a pending invite token can replay it to obtain a passkey-registration credential and register their own passkey on the invited account.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: register their own passkey on the invited account, taking control of that account
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: For a staff or tenant-admin invite this yields access to the tenant context tied to that account.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    subtechnique_id: T1110.001
    subtechnique_name: Password Guessing
    evidence: A returning client's six-digit booking PIN can be brute-forced online in the victim tenant.
    confidence_band: high
cves:
  - id: CVE-2026-58202
    cvss: 8.3
    kev_status: "false"
  - id: CVE-2026-65824
    cvss: 7.4
    epss: 0.00252
    kev_status: "false"
  - id: CVE-2026-65825
    cvss: 7.5
    epss: 0.00216
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58202
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65824
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65825
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
    - SOC
  immediate_actions:
    - action: Upgrade all OpenReception instances to version 2.0.0 or later.
      owner: IT Operations
      due: 24h
      evidence: This issue has been patched in version 2.0.0.
    - action: Upgrade OpenReception appointment booking software to version 2.2.1.
      owner: IT Operations
      due: 48h
      evidence: This issue has been patched in version 2.2.1.
    - action: Implement rate-limiting or account lockout thresholds for appointment booking PIN verification endpoints.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability allows brute-forcing of a six-digit PIN.
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
    - lead: Identify anomalous passkey registrations originating from unknown IP addresses or occurring in high volume.
      data_needed:
        - Application audit logs
        - Authentication logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: attacker... replay it to... register their own passkey on the invited account
    - lead: Identify abnormal spikes in failed authentication attempts directed at appointment booking PIN verification endpoints.
      technique_id: T1110.001
      data_needed:
        - Web server access logs
        - Application authentication logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: A returning client's six-digit booking PIN can be brute-forced online in the victim tenant.
  mitigation_plan:
    - priority: immediate
      action: Configure the front-end proxy (e.g., Caddy, Nginx) to enforce explicit tenant domains and block requests with unrecognized Host headers.
      owner: IT Operations
      addresses: CVE-2026-58202
      evidence: 'Reaching the app with a spoofed Host depends on the front proxy: the stock Caddy catch-all forwards it, while an operator who configures explicit per-tenant proxy blocks is not affected.'
    - priority: immediate
      action: Upgrade to 2.2.1
      owner: IT Operations
      addresses: CVE-2026-65824
      evidence: patched in version 2.2.1
    - priority: immediate
      action: Monitor vendor communications for an update addressing CVE-2026-65825.
      owner: IT Operations
      addresses: CVE-2026-65825
      evidence: At time of publication, there are no publicly available patches.
updates:
  - at: "2026-10-29T20:01:06Z"
    level: L2
    summary: added coverage for appointment booking software (< 2.2.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-65824
  - at: "2026-10-29T20:01:11Z"
    level: L2
    summary: added coverage for appointment booking software (<= 2.1.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-65825
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
