---
title: Insecure Deserialization in Cotonti Comments Plugin
slug: 2026-09-cotonti-unserialize-rce
description: Cotonti version 1.0.0 contains an insecure deserialization vulnerability in the comments plugin allowing authenticated users to trigger object injection and potential remote code execution.
date: "2026-09-18T22:11:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cotonti:cotonti:*:*:*:*:*:*:*:*
tags:
  - web-application
  - deserialization
  - vulnerability
vendors:
  - Cotonti
products:
  - Cotonti (1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The application passes user-supplied base64-decoded input from the 'cb' parameter directly into the PHP unserialize() function.
    confidence_band: high
cves:
  - id: CVE-2026-93872
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93872
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review web logs for suspicious 'cb' parameter payloads in comments
      owner: SOC
      due: 24h
      evidence: Source describes 'cb' parameter as the injection vector
  mitigation_plan:
    - priority: immediate
      action: Disable the comments plugin or restrict write access to 'cb' parameter until a patch is available
      owner: IT Operations
      addresses: CVE-2026-93872
      evidence: Vulnerability in comments plugin EditAction
---

Cotonti version 1.0.0 is affected by an insecure deserialization vulnerability within its comments plugin, specifically within the EditAction function. The application accepts a 'cb' parameter from the user, which is base64-decoded and passed directly to the PHP `unserialize()` function without implementing `allowed_classes` restrictions. This design flaw allows authenticated users who possess comment write permissions to inject and instantiate arbitrary PHP objects. If a suitable gadget chain exists within the application's codebase or dependencies, an attacker can leverage this primitive to achieve file write operations or remote code execution. This vulnerability represents a significant risk to the integrity and availability of the platform, as it permits authenticated low-privileged users to elevate their impact to server-side code execution.

## Impact

The vulnerability allows for potential remote code execution and arbitrary file writes on servers running Cotonti 1.0.0. An attacker must have a registered account with comment write permissions to exploit this flaw. Successful exploitation can lead to a full system compromise, data exfiltration, or unauthorized modification of the website's backend infrastructure.

## Recommendation

Detection engineering teams should focus on identifying abnormal HTTP traffic patterns associated with the 'cb' parameter in comment-related requests. 

- Monitor web server logs for requests to the comments plugin that contain base64-encoded strings within the 'cb' parameter.
- Audit PHP code and dependencies for vulnerable classes or gadgets that could be combined with `unserialize()` to facilitate exploit chains.
- Restrict application permissions where possible to limit the number of users capable of interacting with the vulnerable EditAction functionality.
