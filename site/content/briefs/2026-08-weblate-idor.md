---
title: IDOR Vulnerability in Weblate GroupViewSet API
slug: 2026-08-weblate-idor
description: An Insecure Direct Object Reference vulnerability (CVE-2026-55228) in the Weblate GroupViewSet API allows authenticated project managers to gain unauthorized read access to private projects via manipulated team configurations.
date: "2026-08-28T21:15:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:weblate:weblate:*:*:*:*:*:*:*:*
tags:
  - idor
  - api-vulnerability
  - access-control
vendors:
  - WeblateOrg
products:
  - Weblate (< 2026.7)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An Insecure Direct Object Reference (IDOR) vulnerability within the GroupViewSet API allows authenticated project managers to gain unauthorized read access to private projects.
    confidence_band: high
cves:
  - id: CVE-2026-55228
    cvss: 8.1
    epss: 0.00227
references:
  - https://github.com/advisories/GHSA-2q2q-jr9g-v9rf
  - https://github.com/WeblateOrg/weblate/pull/19970
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55228
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Weblate to version 2026.7 or later.
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies 2026.7 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2026.7 or later.
      owner: IT Operations
      addresses: CVE-2026-55228
      evidence: GHSA-2q2q-jr9g-v9rf
---

Weblate, an open-source translation tool, is affected by a security vulnerability (CVE-2026-55228) in the GroupViewSet API. This Insecure Direct Object Reference (IDOR) flaw permits an authenticated user with project manager privileges to bypass existing authorization controls. By submitting requests that manipulate project- and workspace-scoped team configurations, attackers can misconfigure project access rights. This action results in unauthorized read access to private projects that the user would otherwise be restricted from viewing. The vulnerability affects all versions of Weblate prior to 2026.7. Defenders should prioritize patching, as this vulnerability allows for the unauthorized exfiltration of sensitive translation project data within multi-tenant or multi-project environments.

## Impact

Successful exploitation grants unauthorized read access to sensitive private projects. In environments where multiple teams share a Weblate instance, this allows project managers to potentially view proprietary intellectual property or sensitive documentation stored within private translation projects. No estimate of victim count is provided, but the vulnerability impacts all organizations self-hosting Weblate versions below 2026.7.

## Recommendation

* Upgrade all Weblate instances to version 2026.7 or later to resolve the underlying API logic flaw in GroupViewSet.
* Review audit logs for unusual API requests directed at the GroupViewSet endpoints that involve project-scoped team modifications.
* Restrict project manager privileges to trusted users until patches can be applied to minimize the window of opportunity for privilege abuse.
