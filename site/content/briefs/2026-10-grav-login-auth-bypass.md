---
brief_id: brief-2026-10-22-grav-login-auth-bypass
event_id: brief-2026-10-22-grav-login-auth-bypass
revision: 1
activity_at: "2026-10-22T03:52:47Z"
title: 'Grav Login Plugin: Missing Authorization in login.invite (CVE-2026-114658)'
slug: 2026-10-grav-login-auth-bypass
description: The Grav Login plugin contains a missing authorization flaw in the login.invite task, allowing unauthenticated attackers to register arbitrary email addresses as super users by manipulating page frontmatter.
date: "2026-10-22T03:52:47Z"
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
  validation_status: Source-based assessment; requires vendor patch application.
cpes:
  - cpe:2.3:a:getgrav:login:*:*:*:*:*:*:*:*
vendors:
  - Grav
products:
  - Login plugin (3.6.0 - 3.9.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can define an invitation form granting super access in page frontmatter, submit it unauthenticated, and register the invited address for full site control.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Grav Login plugin contains a missing authorization vulnerability in the login.invite task that allows page authors to obtain super user accounts.
    confidence_band: high
cves:
  - id: CVE-2026-114658
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114658
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Grav Login plugin to 3.9.13 or later
      owner: IT Operations
      addresses: CVE-2026-114658
      evidence: Source NIST NVD advisory
---

The Grav Login plugin (versions 3.6.0 through 3.9.12) is vulnerable to a missing authorization issue within the `login.invite` task. An unauthenticated attacker can exploit this by crafting or locating a page with specific frontmatter that enables an invitation form granting super user privileges. By submitting this form, the attacker can register an arbitrary email address and gain full administrative access to the Grav instance.

## Impact

Successful exploitation allows an unauthenticated attacker to obtain super user accounts, resulting in full site control and administrative compromise of the affected Grav instance.

## Recommendation

- Upgrade the Grav Login plugin to version 3.9.13 or later immediately to address the missing authorization flaw.
- Review existing site pages and frontmatter configurations for unauthorized or unexpected invitation form definitions.
- Audit existing user accounts for suspicious registrations or unauthorized administrative escalations.
