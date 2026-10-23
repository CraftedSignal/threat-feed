---
brief_id: brief-2026-10-23-plone-info-disclosure
event_id: brief-2026-10-23-plone-info-disclosure
revision: 1
activity_at: "2026-10-23T04:06:05Z"
title: 'Plone: Unauthenticated user enumeration via plone.app.content'
slug: 2026-10-plone-info-disclosure
description: An information disclosure vulnerability in plone.app.content allows unauthenticated attackers to enumerate site users and groups when the Plone REST API is enabled.
date: "2026-10-23T04:06:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for deployment
tags:
  - information-disclosure
  - reconnaissance
  - web-application
vendors:
  - Plone
products:
  - plone.app.content
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: 'Summary: the users and groups of a Plone site can be listed by an unauthenticated user.'
    confidence_band: high
references:
  - https://seclists.org/oss-sec/2026/q4/334
  - https://github.com/plone/plone.app.content/security/advisories/GHSA-vhwp-qc29-j4xp
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch plone.app.content to the version specified in the advisory
      owner: IT Operations
      due: 48h
      evidence: Vulnerability advisory GHSA-vhwp-qc29-j4xp
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected Plone components to the patched version identified in the advisory
      owner: IT Operations
      addresses: plone.app.content information disclosure
      evidence: Plone security fix 20261022
---

The Plone security team has disclosed an information disclosure vulnerability in `plone.app.content` (GHSA-vhwp-qc29-j4xp). The flaw permits unauthenticated users to list all users and groups registered on a Plone site. The leaked information includes specific user IDs and full names. The vulnerability affects Plone installations where the Plone REST API is enabled.

## Impact

Successful exploitation allows for the enumeration of organizational user directories, providing an attacker with a list of valid usernames that can be used for subsequent password spraying, phishing, or targeted social engineering campaigns.

## Recommendation

- Identify all Plone instances running `plone.app.content` and verify if the REST API is exposed.
- Review the security advisory at https://github.com/plone/plone.app.content/security/advisories/GHSA-vhwp-qc29-j4xp for specific patching instructions and version updates.
- Apply the vendor-provided patch or upgrade to the non-vulnerable version as specified in the advisory.
