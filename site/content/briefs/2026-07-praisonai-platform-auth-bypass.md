---
title: 'CVE-2026-61442: PraisonAI Platform Authorization Bypass'
slug: 2026-07-praisonai-platform-auth-bypass
description: PraisonAI Platform versions before 0.1.9 are vulnerable to an authorization bypass on PATCH routes for projects, issues, and agents, allowing an attacker with a workspace-member role to modify owner-created records, reassign the lead_id to their own user ID, and subsequently delete owner-created projects, bypassing standard permission checks and leading to unauthorized data manipulation and deletion.
date: "2026-07-11T14:25:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - vulnerability
  - web-application
  - cve
vendors:
  - MervinPraison
products:
  - PraisonAI Platform < 0.1.9
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A workspace member can modify owner-created records; for projects, a member can reassign lead_id to their own user id and then delete the owner-created project, bypassing the delete route's owner/admin permission check.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: '...and then delete the owner-created project, bypassing the delete route''s owner/admin permission check.'
    confidence_band: high
cves:
  - id: CVE-2026-61442
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61442
  - https://github.com/MervinPraison/PraisonAI/commit/846568c7a5d8ce9e71e56e4c213f027c04909753
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-c78w-2q4r-68r7
  - https://www.vulncheck.com/advisories/praisonai-platform-before-authorization-bypass-via-patch
---

CVE-2026-61442 identifies a critical authorization bypass vulnerability in PraisonAI Platform (praisonai-platform) versions prior to 0.1.9. This flaw stems from inadequate permission enforcement on specific PATCH routes for projects, issues, and agents. While these routes should ideally require owner or administrator privileges for sensitive modifications, they currently only check for a workspace-member role. This allows any authenticated workspace member to modify records created by owners. Specifically, an attacker can reassign the `lead_id` of an owner-created project to their own user ID. This unauthorized change effectively grants them ownership over that project, enabling them to then delete the project, circumventing the explicit owner/admin permission check on the delete route. This vulnerability poses a significant risk of unauthorized data loss and integrity compromise within the platform.

## Attack Chain

1. An attacker gains authenticated access to the PraisonAI Platform as a legitimate workspace member with low-level privileges.
2. The attacker identifies a target project, issue, or agent record that was created by a platform owner or administrator.
3. The attacker crafts and sends an HTTP PATCH request to the PraisonAI Platform's PATCH route for the identified project.
4. Within the PATCH request payload, the attacker includes a modification to the `lead_id` field, assigning it to their own user ID.
5. Due to the missing authorization enforcement (CWE-862) on the PATCH route, the platform accepts and processes this request, changing the project's lead to the attacker.
6. The attacker then initiates an HTTP DELETE request for the now-modified project.
7. Because the attacker's user ID is now associated as the `lead_id` for the project, the platform's delete route permission check is bypassed, incorrectly treating the attacker as authorized.
8. The owner-created project is successfully deleted by the attacker, leading to unauthorized data destruction.

## Impact

Successful exploitation of CVE-2026-61442 allows an authenticated workspace member to perform unauthorized data manipulation and deletion of critical owner-created records within the PraisonAI Platform. This can lead to significant data integrity issues, including the irreversible loss of project data, issues, or agent configurations. The vulnerability has a CVSS v3.1 base score of 7.1 (High), reflecting its significant potential for impact on availability and integrity. While no specific victim counts are available, any organization utilizing PraisonAI Platform versions before 0.1.9 is at risk of internal users maliciously or accidentally destroying sensitive data.

## Recommendation

* Patch PraisonAI Platform to version 0.1.9 or later immediately to address CVE-2026-61442, as indicated by the advisories in the references.
* Review access logs for PATCH requests to `/projects/*`, `/issues/*`, or `/agents/*` routes in the PraisonAI Platform for unauthorized modifications of `lead_id` or similar ownership fields by non-admin accounts.
