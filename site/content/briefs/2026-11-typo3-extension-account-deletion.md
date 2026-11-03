---
brief_id: brief-2026-11-03-typo3-extension-account-deletion
event_id: brief-2026-11-03-typo3-extension-account-deletion
revision: 1
activity_at: "2026-11-03T12:08:58Z"
title: 'TYPO3: Unauthenticated Account Deletion and Information Disclosure (CVE-2026-120333)'
slug: 2026-11-typo3-extension-account-deletion
description: A high-severity vulnerability in a TYPO3 extension allows unauthenticated attackers to delete arbitrary frontend user accounts and retrieve sensitive user information by bypassing hash validation on action links.
date: "2026-11-03T12:08:58Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment-specific inventory
cpes:
  - cpe:2.3:a:typo3:extension:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - cve-2026-120333
vendors:
  - TYPO3
products:
  - TYPO3 extension (typo3-ext-sa-2026-038)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can therefore perform these actions for arbitrary active frontend users.
    confidence_band: high
cves:
  - id: CVE-2026-120333
    kev_status: "false"
references:
  - https://typo3.org/security/advisory/typo3-ext-sa-2026-038
  - https://sploitus.com/exploit?id=CVE-2026-120333
  - https://sploitus.com/exploit?id=CVE-2026-120333&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all TYPO3 installations and check for the vulnerable extension version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-120333 advisory
  hunt_leads:
    - lead: Search web server logs for requests to action links (registration/deletion) that do not contain the expected hash parameter
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The actions linked in the emails of the extension do not reject requests with a missing or invalid hash.
  mitigation_plan:
    - priority: immediate
      action: Patch TYPO3 extension according to vendor instructions at typo3-ext-sa-2026-038
      owner: IT Operations
      addresses: CVE-2026-120333
      evidence: https://typo3.org/security/advisory/typo3-ext-sa-2026-038
---

CVE-2026-120333 affects a TYPO3 extension where account-related action links (such as those for registration confirmation or account deletion) fail to properly validate or require a hash parameter. An unauthenticated attacker can exploit this by manipulating the request to target arbitrary frontend users. Successful exploitation results in the unauthorized retrieval of usernames and email addresses, as well as the deletion of frontend user accounts.

## Impact

Successful exploitation allows unauthenticated attackers to perform administrative-level actions on frontend user accounts, specifically the retrieval of PII (usernames, email addresses) and the deletion of user accounts.

## Recommendation

- Identify all instances of the affected TYPO3 extension within the environment.
- Apply the security update provided by the TYPO3 security team at https://typo3.org/security/advisory/typo3-ext-sa-2026-038.
- Review web server access logs for anomalous HTTP requests targeting registration or deletion confirmation endpoints that lack standard cryptographic hash tokens.
