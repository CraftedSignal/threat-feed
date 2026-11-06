---
brief_id: brief-2026-11-06-catalyst-auth-timing-attack
event_id: brief-2026-11-06-catalyst-auth-timing-attack
revision: 1
activity_at: "2026-11-06T21:29:25Z"
title: 'Catalyst::Plugin::Authentication: Timing attack vulnerability in legacy password verifier (CVE-2026-74846)'
slug: 2026-11-catalyst-auth-timing-attack
description: Catalyst::Plugin::Authentication for Perl versions prior to 0.10029 are vulnerable to remote timing attacks due to insecure string comparison operators in the legacy password verifier.
date: "2026-11-06T21:29:25Z"
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
cpes:
  - cpe:2.3:a:catalyst_project:catalyst-plugin-authentication:*:*:*:*:*:perl:*:*
products:
  - Catalyst::Plugin::Authentication (< 0.10029)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.001
    technique_name: Password Guessing
    subtechnique_id: T1110.001
    subtechnique_name: Password Guessing
    evidence: A remote attacker can use response-time differences to guess the stored password or hash.
    confidence_band: high
cves:
  - id: CVE-2026-74846
    cvss: 7.5
    epss: 0.00273
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74846
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Catalyst::Plugin::Authentication to version 0.10029 or later
      owner: IT Operations
      due: 72h
      evidence: Catalyst::Plugin::Authentication versions before 0.10029 for Perl allow timing attacks
  hunt_leads:
    - lead: Identify endpoints utilizing the deprecated login method
      data_needed:
        - Application source code
        - Authentication logs showing login methods
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The legacy verifier, used by the deprecated login method, compares clear-text passwords
  mitigation_plan:
    - priority: immediate
      action: Upgrade Catalyst::Plugin::Authentication to 0.10029 or later
      owner: IT Operations
      addresses: CVE-2026-74846
      evidence: Catalyst::Plugin::Authentication versions before 0.10029 for Perl allow timing attacks
---

The Catalyst::Plugin::Authentication module for Perl contains a vulnerability in its legacy password verifier that allows remote timing attacks. The legacy verifier, utilized by a deprecated login method, performs password comparisons using the Perl 'eq' operator. Because this operator exits early when a mismatch is found, the total execution time of the comparison varies based on the number of matching leading bytes. An attacker can exploit these response-time differences to perform statistical analysis and recover stored passwords or password hashes.

## Impact

Successful exploitation allows remote attackers to recover stored credentials or password hashes through iterative measurement of authentication response times.

## Recommendation

* Update the Catalyst::Plugin::Authentication package to version 0.10029 or later to remove the vulnerable legacy verifier.
* Identify and migrate any applications or modules currently utilizing the deprecated 'login' method to the modern, realm-based verifier which is not subject to this vulnerability.
* Monitor authentication logs for high volumes of login requests originating from a single source or targeting specific accounts, which may indicate an ongoing timing attack.
