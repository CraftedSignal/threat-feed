---
title: Missing Authorization Vulnerability in Shaark API
slug: 2026-10-shaark-auth-bypass
description: Shaark versions 1.2.13 through 1.2.44 contain a missing authorization vulnerability in multiple API controllers, allowing authenticated non-admin users to modify or delete content belonging to other users.
date: "2026-10-12T22:42:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:shaark:shaark:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authorization-bypass
  - api-security
vendors:
  - Shaark
products:
  - Shaark (1.2.13 through 1.2.44)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Authenticated non-admin users can send PUT or DELETE requests... to overwrite or delete other users' content.
    confidence_band: high
cves:
  - id: CVE-2026-109568
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109568
rules:
  - title: Detect CVE-2026-109568 Exploitation - Unauthorized API Modification
    description: Detects potential exploitation of CVE-2026-109568 by monitoring for PUT or DELETE requests to sensitive Shaark API endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1565.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Shaark to a version beyond 1.2.44
      owner: IT Operations
      due: 48h
      evidence: Source states versions 1.2.13 through 1.2.44 contain the vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest patched version
      owner: IT Operations
      addresses: CVE-2026-109568
      evidence: NVD vulnerability disclosure
---

Shaark versions 1.2.13 through 1.2.44 are affected by a missing authorization vulnerability within the Link, Story, Chest, and Album API controllers. The vulnerability stems from a failure to perform adequate ownership checks during API requests, which allows any authenticated, non-administrative user to interact with resources they do not own. By submitting crafted PUT or DELETE requests to the /api/link/{id}, /api/story/{id}, /api/chest/{id}, or /api/album/{id} endpoints with valid numeric identifiers, an attacker can overwrite or remove content belonging to other users, including items marked as private. This vulnerability significantly impacts the confidentiality and integrity of user data within the application.

## Impact

Successful exploitation allows authenticated users to perform unauthorized destructive or modification operations on resources belonging to other users, including private content. This can lead to total data loss for specific user items or unauthorized modification of shared resources, potentially affecting any multi-user deployment of the Shaark application.

## Recommendation

Update the Shaark application to a version beyond 1.2.44 immediately. Detection teams should monitor web server access logs for anomalous patterns of PUT or DELETE requests directed at the specified API controllers, particularly those involving sequential or high-volume ID increments from non-administrative user accounts.
