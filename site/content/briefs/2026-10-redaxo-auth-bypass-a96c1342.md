---
brief_id: brief-2026-10-27-redaxo-auth-bypass-a96c1342
event_id: brief-2026-10-27-redaxo-auth-bypass-a96c1342
revision: 2
activity_at: "2026-10-29T20:15:56Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:15:56Z"
    checksum: sha256:fcfda97f31006201983f13c2382fcd577a4da1cec3584058846846d0061482d4
    summary: added coverage for REDAXO (< 5.21.4)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - references
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116898
title: 'REDAXO: Authorization bypass in backup addon (CVE-2026-116896)'
slug: 2026-10-redaxo-auth-bypass-a96c1342
description: REDAXO versions prior to 5.21.5 contain a missing authorization flaw in the backup addon that allows unauthorized export of sensitive database tables.
date: "2026-10-27T11:46:51Z"
lastmod: "2026-10-29T20:13:42Z"
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
  validation_status: Source-verified
cpes:
  - cpe:2.3:a:redaxo:redaxo:*:*:*:*:*:*:*:*
vendors:
  - REDAXO
products:
  - REDAXO (< 5.21.5)
  - REDAXO (< 5.21.3)
  - REDAXO (< 5.21.4)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can obtain plaintext session ids and stay-logged-in keys to take over admin accounts, or password hashes for offline cracking.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated backend users with permission for one media category can move files from restricted categories into it.
    confidence_band: high
cves:
  - id: CVE-2026-116896
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-117536
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-116898
    cvss: 7.1
    epss: 0.00168
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116896
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117536
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116898
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch REDAXO to 5.21.5
      owner: IT Operations
      due: 48h
      evidence: REDAXO before 5.21.5 contains a missing authorization vulnerability
    - action: Upgrade REDAXO to 5.21.3 or later
      owner: IT Operations
      due: 48h
      evidence: REDAXO before 5.21.3 contains a cross-site request forgery vulnerability
  hunt_leads:
    - lead: Identify unauthorized database exports initiated by users with backup[export] privileges
      technique_id: T1005
      data_needed:
        - Application access logs tracking backup addon usage
        - Database export event logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Users with the backup[export] permission can inappropriately access sensitive database tables
    - lead: Identify suspicious GET requests to user administration backend pages that include FUNC_UPDATE
      technique_id: T1521
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: the update path triggered by FUNC_UPDATE does not require it [a CSRF token]
    - lead: Identify backend users performing bulk move operations on media files
      technique_id: T1068
      data_needed:
        - Web server access logs
        - REDAXO application audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability exists in the media pool bulk move functionality.
  mitigation_plan:
    - priority: immediate
      action: Upgrade REDAXO to 5.21.5
      owner: IT Operations
      addresses: CVE-2026-116896
      evidence: REDAXO before 5.21.5 contains a missing authorization vulnerability
    - priority: immediate
      action: Apply security update to version 5.21.3
      owner: IT Operations
      addresses: CVE-2026-117536
      evidence: REDAXO before 5.21.3 contains a cross-site request forgery vulnerability
    - priority: immediate
      action: Upgrade REDAXO to version 5.21.4 or later
      owner: IT Operations
      addresses: CVE-2026-116898
      evidence: Fixed in 5.21.4
updates:
  - at: "2026-10-27T11:47:00Z"
    level: L2
    summary: added coverage for REDAXO (< 5.21.3)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-117536
  - at: "2026-10-29T20:13:42Z"
    level: L2
    summary: added coverage for REDAXO (< 5.21.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116898
---

REDAXO versions before 5.21.5 contain a missing authorization vulnerability in the backup addon. Users possessing the 'backup[export]' permission can export arbitrary database tables, including 'rex_user' and 'rex_user_session', which contain sensitive credentials such as plaintext session IDs, persistent login keys, and password hashes. This allows attackers to perform account takeover or offline password cracking.

## Impact
Unauthorized access to sensitive database tables allows non-administrative users to extract credentials and session data, facilitating full administrative account takeover.

## Recommendation
- Upgrade REDAXO to version 5.21.5 or later immediately.
- Review access control lists and revoke the 'backup[export]' permission from any user accounts that do not strictly require it for operational duties.
- Audit database export logs for unusual activity or unauthorized file access attempts.
