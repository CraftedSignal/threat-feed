---
title: Cross-Site Scripting Vulnerability in Ghost ActivityPub Client
slug: 2026-08-ghost-xss
description: An XSS vulnerability in the @tryghost/activitypub package (CVE-2026-53950) allows attackers to inject arbitrary JavaScript via malicious ActivityPub server posts.
date: "2026-08-05T02:00:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - activitypub
vendors:
  - Ghost
products:
  - '@tryghost/activitypub (< 3.1.0)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The ActivityPub client in Ghost was vulnerable to JavaScript injection on posts shared by a maliciously customised ActivityPub server.
    confidence_band: high
cves:
  - id: CVE-2026-53950
    cvss: 7.5
    epss: 0.00204
references:
  - https://github.com/advisories/GHSA-xpp7-93x6-v29m
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53950
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @tryghost/activitypub to 3.1.0
      owner: IT Operations
      due: 24h
      evidence: Advisory states @tryghost/activitypub v3.1.0 contains a fix for this issue.
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2026-53950
      owner: IT Operations
      addresses: CVE-2026-53950
      evidence: Advisory specifies version 3.1.0 contains the fix.
---

A high-severity cross-site scripting (XSS) vulnerability, tracked as CVE-2026-53950, affects the @tryghost/activitypub package used by the Ghost platform. The vulnerability arises from improper sanitization of content ingested from remote ActivityPub servers. By configuring a malicious ActivityPub server, an attacker can craft posts containing arbitrary JavaScript payloads. When these posts are fetched and rendered by the Ghost ActivityPub client, the payload executes in the context of the user's session. This vulnerability impacts all versions of @tryghost/activitypub prior to 3.1.0. Defenders should note that Ghost instances automatically fetch the patched version (v3.1.0) upon release, but administrators should verify the version status of their local deployments to ensure the update has been applied.

## Impact

Successful exploitation allows for unauthorized script execution in the context of the user viewing the malicious post. This can lead to session hijacking, unauthorized actions performed on behalf of the user, or the exfiltration of sensitive information accessible through the browser session. All Ghost deployments utilizing the affected @tryghost/activitypub package are vulnerable if not updated to version 3.1.0 or later.

## Recommendation

- Update the @tryghost/activitypub package to version 3.1.0 or later immediately to incorporate the sanitization fix for CVE-2026-53950.
- Review web server and application logs for suspicious inbound ActivityPub traffic if there is evidence of targeting.
- Audit the Ghost installation directory to confirm the current version of the @tryghost/activitypub dependency.
