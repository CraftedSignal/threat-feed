---
title: IDOR Vulnerability in LingGuo-Drama
slug: 2026-10-lingguo-drama-idor
description: LingGuo-Drama through commit 8a6924a is vulnerable to an Insecure Direct Object Reference (IDOR) flaw allowing unauthorized access, modification, and deletion of user projects.
date: "2026-10-16T18:51:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lingguo:drama:*:*:*:*:*:*:*:*
tags:
  - idor
  - web-application-vulnerability
  - vulnerability
vendors:
  - LingGuo
products:
  - Drama (through commit 8a6924a)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Self-registered attackers can iterate numeric IDs via GET, PUT and DELETE /admin/v1/projects/:id to read, overwrite, reassign or delete any user's short-drama projects.
    confidence_band: high
cves:
  - id: CVE-2026-111722
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111722
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review web access logs for patterns of enumeration on /admin/v1/projects/:id
      owner: SOC
      due: 24h
      evidence: Source documentation of the IDOR vector
  mitigation_plan:
    - priority: immediate
      action: Patch LingGuo-Drama beyond commit 8a6924a or restrict access to /admin/v1/projects/ endpoints
      owner: IT Operations
      addresses: CVE-2026-111722
      evidence: NVD vulnerability disclosure
---

LingGuo-Drama, an application for managing short-drama projects, contains an Insecure Direct Object Reference (IDOR) vulnerability identified as CVE-2026-111722. The vulnerability exists in the projects.Get function, which fails to validate project ownership during access requests. By manipulating numeric identifiers within the API, a self-registered user can bypass authorization controls. The impact is significant, as an attacker can read, overwrite, reassign, or delete any project hosted on the instance, regardless of whether they own it. This issue affects all versions of the application up to and including commit 8a6924a. Defenders should prioritize auditing web server access logs for anomalous patterns of sequential numeric ID requests to the project management API endpoints.

## Impact

Successful exploitation allows an unprivileged, self-registered user to access and manipulate data belonging to other users. This can lead to total loss of project confidentiality, integrity, and availability within the impacted LingGuo-Drama instance. The vulnerability poses a high risk to any organization hosting this software, as it requires no elevated privileges to execute unauthorized administrative actions on project objects.

## Recommendation

- Identify all instances of LingGuo-Drama running versions up to commit 8a6924a and evaluate the necessity of exposure to untrusted users.
- Implement strict authorization logic in the projects.Get function to ensure that the requester's ID matches the project owner's ID.
- Monitor web server logs for high-frequency GET, PUT, or DELETE requests to /admin/v1/projects/:id where the :id parameter follows a sequential pattern.
- Patch or upgrade the LingGuo-Drama instance immediately upon the availability of a vendor-supplied fix that addresses the missing authorization check.
