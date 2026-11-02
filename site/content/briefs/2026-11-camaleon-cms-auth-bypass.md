---
brief_id: brief-2026-11-02-camaleon-cms-auth-bypass
event_id: brief-2026-11-02-camaleon-cms-auth-bypass
revision: 1
activity_at: "2026-11-02T15:48:33Z"
title: 'Camaleon CMS: Missing authorization in MediaController (CVE-2026-120429)'
slug: 2026-11-camaleon-cms-auth-bypass
description: Camaleon CMS versions prior to 2.9.2 contain an authorization bypass vulnerability allowing low-privileged users to perform unauthorized file operations and modify user avatars.
date: "2026-11-02T15:48:33Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:camaleon_cms:camaleon_cms:*:*:*:*:*:*:*:*
vendors:
  - Camaleon CMS
products:
  - Camaleon CMS (< 2.9.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Camaleon CMS before 2.9.2 contains a missing authorization vulnerability in Admin::MediaController that allows low-privileged authenticated users to bypass the role-based Media permission.
    confidence_band: high
cves:
  - id: CVE-2026-120429
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120429
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Camaleon CMS to version 2.9.2 or later.
      owner: IT Operations
      due: 72h
      evidence: Camaleon CMS before 2.9.2 contains a missing authorization vulnerability.
  hunt_leads:
    - lead: Identify unauthorized access to sensitive media routes and avatar modification requests by non-admin users.
      technique_id: T1068
      data_needed:
        - Web server access logs or application audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can POST to /admin/media/upload to store files, read private media via download_private_file, and use crop with saved_avatar.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Camaleon CMS 2.9.2.
      owner: IT Operations
      addresses: CVE-2026-120429
      evidence: Camaleon CMS before 2.9.2 contains a missing authorization vulnerability.
---

Camaleon CMS versions before 2.9.2 contain a missing authorization vulnerability within the `Admin::MediaController`. This flaw allows authenticated users with low privileges to bypass role-based permission checks. An attacker can exploit this to upload arbitrary files, access private media files via `download_private_file`, and manipulate other users' avatars by calling the `crop` function with `saved_avatar`.

## Impact
Successful exploitation allows low-privileged users to read sensitive private media files, perform unauthorized file uploads, and perform account-level modification by altering user avatars.

## Recommendation
- Upgrade Camaleon CMS to version 2.9.2 or later to apply the authorization checks for media management.
- Audit administrative media logs for unexpected file uploads or avatar modifications performed by low-privileged user accounts.
