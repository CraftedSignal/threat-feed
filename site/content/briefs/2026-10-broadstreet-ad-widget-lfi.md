---
brief_id: brief-2026-10-22-broadstreet-ad-widget-lfi
event_id: brief-2026-10-22-broadstreet-ad-widget-lfi
revision: 1
activity_at: "2026-10-22T14:14:20Z"
title: 'Broadstreet Ad Widget: Local File Inclusion in views/modal/index.php (CVE-2017-20289)'
slug: 2026-10-broadstreet-ad-widget-lfi
description: The Broadstreet Ad Widget WordPress plugin (versions 2.2.0 through 2.11.9) is vulnerable to authenticated local file inclusion via directory traversal in the 'step' parameter, allowing for arbitrary PHP code execution.
date: "2026-10-22T14:14:20Z"
type: threat
types:
  - threat
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
  validation_status: Verified against CVE details
cpes:
  - cpe:2.3:a:broadstreet:broadstreet_ad_widget:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - lfi
  - web-vulnerability
vendors:
  - Broadstreet
products:
  - Broadstreet Ad Widget (2.2.0 - 2.11.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Broadstreet Ad Widget plugin for WordPress 2.2.0 before 2.12.0 contains a local file inclusion vulnerability that allows authenticated users to execute attacker-chosen PHP files.
    confidence_band: high
cves:
  - id: CVE-2017-20289
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20289
rules:
  - title: Detect CVE-2017-20289 Exploitation - LFI via Broadstreet Ad Widget
    description: Detects exploitation attempts against CVE-2017-20289 by identifying directory traversal patterns in the 'step' parameter of the vulnerable index.php file.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Broadstreet Ad Widget to 2.12.0
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies version 2.12.0 as the fix
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to 2.12.0
      owner: IT Operations
      addresses: CVE-2017-20289
      evidence: Plugin version requirement
---

Broadstreet Ad Widget versions 2.2.0 through 2.11.9 contain a local file inclusion (LFI) vulnerability. The vulnerability resides in `views/modal/index.php`, where the `step` parameter is processed without sufficient sanitization before being passed to a PHP `require` statement. Authenticated attackers can leverage directory traversal sequences, potentially combined with null bytes, to include and execute arbitrary local PHP files. This vulnerability has been documented as exploited in the wild since October 19, 2023.

## Impact

Successful exploitation allows authenticated attackers to execute arbitrary PHP code on the underlying web server, potentially leading to full site compromise.

## Recommendation

- Upgrade the Broadstreet Ad Widget plugin to version 2.12.0 or later immediately.
- Audit logs for HTTP GET or POST requests containing directory traversal sequences (e.g., ../) targeting `views/modal/index.php`.
- Restrict administrative or plugin-configuration access to known, trusted users to prevent unprivileged exploitation.
