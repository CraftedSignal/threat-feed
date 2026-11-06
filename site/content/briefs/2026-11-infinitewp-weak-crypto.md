---
brief_id: brief-2026-11-06-infinitewp-weak-crypto
event_id: brief-2026-11-06-infinitewp-weak-crypto
revision: 1
activity_at: "2026-11-06T19:22:48Z"
title: 'InfiniteWP Client: Weak 31-bit cryptographic signing key in NOSSL mode'
slug: 2026-11-infinitewp-weak-crypto
description: InfiniteWP Client version 1.13.10 uses a 31-bit entropy signing key for its NOSSL authentication branch, allowing for practical brute-force recovery and permanent bypass of secure RSA authentication.
date: "2026-11-06T19:22:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
vendors:
  - InfiniteWP
products:
  - InfiniteWP Client (<= 1.13.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: The stored key is generated as [a weak 31-bit value], making it vulnerable to brute-force attacks.
    confidence_band: high
references:
  - https://seclists.org/oss-sec/2026/q4/563
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify WordPress sites running InfiniteWP Client version 1.13.10 or earlier.
      owner: IT Operations
      due: 24h
      evidence: Plugin version vulnerability disclosure
  hunt_leads:
    - lead: Identify WordPress configurations with NOSSL mode enabled
      technique_id: T1552.001
      data_needed:
        - WordPress database entries for wp_options or plugin-specific config tables
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: NOSSL mode is selected by the enrolling panel setting one request parameter and is permanent.
  mitigation_plan:
    - priority: immediate
      action: Disable NOSSL authentication mode in InfiniteWP Client settings and force transition to RSA-based authentication.
      owner: IT Operations
      addresses: NOSSL authentication vulnerability
      evidence: NOSSL mode is permanently selected once the key is stored.
---

InfiniteWP Client version 1.13.10, a WordPress management plugin, contains a critical cryptographic vulnerability in its "NOSSL" authentication branch. This branch is triggered by an enrolling management panel setting a specific request parameter, even on hosts capable of robust RSA verification. Once the NOSSL mode is active, it becomes the permanent authentication method, rendering the secure RSA branch unreachable. The signing key is generated with only 31 bits of entropy, which has been demonstrated to be recoverable via brute-force in under five minutes.

## Impact
Successful recovery of the weak 31-bit signing key allows an attacker to bypass authentication, effectively granting full management control over the affected WordPress installation.

## Recommendation
- Inventory all WordPress instances running the InfiniteWP Client plugin.
- Audit the 'NOSSL' configuration setting within the plugin settings to identify and revert instances currently utilizing this insecure authentication branch.
- Monitor for unauthorized authentication attempts or unexpected changes in management panel enrollment settings on WordPress sites.
- Evaluate the necessity of the NOSSL branch and prioritize migration to the secure RSA-based authentication flow.
