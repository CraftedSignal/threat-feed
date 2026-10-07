---
title: Stored XSS in Ghost via File Uploads
slug: 2026-10-ghost-xss
description: Ghost versions 6.22.1 through 6.64.0 are vulnerable to stored cross-site scripting due to improper Content-Type handling in the local storage adapter, allowing staff-level users to execute malicious scripts on the site domain.
date: "2026-10-07T22:50:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ghost:ghost:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - cve-2026-105679
vendors:
  - Ghost Foundation
products:
  - Ghost (6.22.1-6.63.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: On sites using the default local storage adapter, this restriction was not applied, so files uploaded by any staff user were served with a content type derived from their file extension.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.004
    technique_name: 'Server Software Component: Web Shell'
    evidence: This could be used to host scripts on the site's domain, possibly resulting in compromise of other staff users' admin sessions.
    confidence_band: high
cves:
  - id: CVE-2026-105679
    cvss: 7.3
    epss: 0.00236
references:
  - https://github.com/advisories/GHSA-gfjp-2p8f-94qv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105679
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Ghost instance to v6.64.0 or later
      owner: IT Operations
      due: 24h
      evidence: v6.64.0 contains a fix for this issue.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to v6.64.0
      owner: IT Operations
      addresses: CVE-2026-105679
      evidence: 'Patches: v6.64.0 contains a fix for this issue.'
---

Ghost, a widely used content management system, contains a security vulnerability (CVE-2026-105679) within its local storage adapter. In affected versions (6.22.1 up to 6.64.0), the application fails to enforce restrictive Content-Type headers when serving uploaded files. Under normal security configurations, platforms serve user-uploaded content with restrictive types to prevent execution. Due to this flaw, files uploaded by staff users are served based on their file extension, enabling an attacker with staff-level privileges to host malicious scripts directly on the application's domain. Successful exploitation allows for the execution of arbitrary JavaScript in the context of other staff users, potentially leading to session hijacking, administrative account compromise, and unauthorized administrative actions within the Ghost instance. Defenders should identify instances running versions within the affected range and prioritize upgrades to v6.64.0 or higher.

## Impact

Successful exploitation results in stored cross-site scripting (XSS), which allows an attacker to compromise administrative sessions of staff users. This impacts the integrity and availability of the Ghost instance by enabling malicious actors to perform administrative tasks, modify site content, or extract sensitive session information. This is particularly critical in environments where multiple staff members collaborate on content publishing.

## Recommendation

- Upgrade all self-hosted Ghost instances to version 6.64.0 or later to patch CVE-2026-105679.
- For Docker-based deployments, pull the latest official Ghost image and follow the standard container update procedures.
- Review administrative staff access logs for suspicious file upload patterns or unusual activity involving the site storage directory.
- If immediate patching is not possible, restrict file upload permissions for non-trusted staff accounts until the environment is updated.
