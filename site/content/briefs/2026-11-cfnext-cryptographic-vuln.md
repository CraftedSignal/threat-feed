---
brief_id: brief-2026-11-03-cfnext-cryptographic-vuln
event_id: brief-2026-11-03-cfnext-cryptographic-vuln
revision: 1
activity_at: "2026-11-03T18:00:52Z"
title: 'CFNext: Weak cryptographic derivation in subscription link (CVE-2026-121450)'
slug: 2026-11-cfnext-cryptographic-vuln
description: CFNext versions before 3.1.0 utilize a weak MD5-based cryptographic derivation for subscription UUIDs, enabling offline brute-force attacks to recover administrative passwords and exfiltrate stored proxy and API credentials.
date: "2026-11-03T18:00:52Z"
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
  validation_status: verified against NVD
cpes:
  - cpe:2.3:a:cfnext:cfnext:*:*:*:*:*:*:*:*
tags:
  - cve-2026-121450
  - cryptography
  - authentication
vendors:
  - CFNext
products:
  - CFNext (< 3.1.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.001
    technique_name: Password Guessing
    evidence: Attackers can brute-force the password offline without rate limiting.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: log into the admin panel, and read stored Trojan, Clash, Telegram and Cloudflare API secrets.
    confidence_band: high
cves:
  - id: CVE-2026-121450
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121450
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade CFNext to 3.1.0 or later
      owner: IT Operations
      due: 48h
      evidence: CFNext before 3.1.0 contains a weak cryptographic derivation vulnerability
  hunt_leads:
    - lead: Identify unauthorized administrative logins occurring after unusual subscription UUID usage
      technique_id: T1110.001
      data_needed:
        - Web access logs (source IP, requested endpoint)
        - Application audit logs (authentication success/failure)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can brute-force the password offline... log into the admin panel
  mitigation_plan:
    - priority: immediate
      action: Upgrade CFNext to 3.1.0
      owner: IT Operations
      addresses: CVE-2026-121450
      evidence: CFNext before 3.1.0 contains a weak cryptographic derivation vulnerability
---

CFNext versions prior to 3.1.0 contain a vulnerability where the subscription UUID is generated using an MD5 hash of the administrator password combined with a static, public salt. This implementation allows unauthorized individuals possessing a valid subscription link to perform offline brute-force attacks to recover the cleartext administrator password. Successful exploitation grants full administrative access to the CFNext panel, allowing the retrieval of sensitive configuration secrets, including Trojan, Clash, Telegram, and Cloudflare API credentials.

## Impact

Successful exploitation results in full administrative compromise of the CFNext instance. Impact includes unauthorized access to system administration functions and the exposure of sensitive service credentials and proxy configuration secrets.

## Recommendation

* Upgrade CFNext to version 3.1.0 or later immediately to remediate the weak cryptographic derivation logic.
* Audit logs for administrative account activity from unrecognized IP addresses, specifically looking for repeated login attempts indicative of brute-forcing or credential stuffing.
* Rotate all API keys and credentials (Trojan, Clash, Telegram, Cloudflare) stored within the CFNext instance if evidence of unauthorized administrative access is detected.
