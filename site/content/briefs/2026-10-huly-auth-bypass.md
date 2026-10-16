---
title: Missing Authorization Vulnerability in Huly Platform
slug: 2026-10-huly-auth-bypass
description: Huly Platform versions through 0.7.432 contain a missing authorization vulnerability in the mergeSpecifiedPersons RPC, enabling authenticated account takeover.
date: "2026-10-16T18:46:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:huly:huly_platform:*:*:*:*:*:*:*:*
tags:
  - identity-management
  - authentication-bypass
  - cve-2026-111606
vendors:
  - Huly
products:
  - Huly Platform (<= 0.7.432)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1136.002
    technique_name: 'Create Account: Domain Account'
    evidence: Attackers knowing two person UUIDs can graft attacker-controlled unverified social ids onto a victim person, then use login or password recovery to take over the victim account.
    confidence_band: high
cves:
  - id: CVE-2026-111606
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111606
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Huly Platform to version 0.7.433 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111606 affects versions 0.7.432 and earlier.
  hunt_leads:
    - lead: Audit logs for 'mergeSpecifiedPersons' RPC calls.
      technique_id: T1136.002
      data_needed:
        - Application audit logs containing RPC call parameters
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit requires calling the mergeSpecifiedPersons account RPC.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Huly Platform to the latest version to address CVE-2026-111606.
      owner: IT Operations
      addresses: CVE-2026-111606
      evidence: NVD vulnerability disclosure.
---

Huly Platform versions through 0.7.432 contain a critical missing authorization vulnerability (CVE-2026-111606) within the 'mergeSpecifiedPersons' account RPC. This flaw allows any authenticated user to merge arbitrary user accounts by providing the corresponding person UUIDs. By leveraging this RPC, an attacker can graft their own unverified social identities onto a victim's account profile. Once the accounts are merged, the attacker can force password recovery or authentication flows to gain full control over the target's account. This vulnerability poses a significant risk to organizational identity integrity within the Huly environment, as it facilitates unauthorized access to arbitrary user accounts without requiring administrative privileges, provided the attacker can identify the target's UUID.

## Impact

The vulnerability results in full account takeover capabilities for any authenticated user within the Huly Platform. This can lead to unauthorized access to sensitive project data, internal communications, and other platform resources associated with the compromised user account. All instances of Huly Platform running versions 0.7.432 and earlier are affected.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Update Huly Platform to a patched version beyond 0.7.432 immediately.
- Review access logs for excessive or unusual calls to the 'mergeSpecifiedPersons' RPC endpoint.
- Monitor for anomalous account identity associations or suspicious social login activity linked to previously established user accounts.
- Implement restrictive access controls on account management RPCs to prevent unauthorized users from performing identity merge operations.
