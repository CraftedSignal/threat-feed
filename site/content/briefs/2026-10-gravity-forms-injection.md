---
brief_id: brief-2026-10-30-gravity-forms-injection
event_id: brief-2026-10-30-gravity-forms-injection
revision: 2
activity_at: "2026-10-31T18:40:45Z"
revision_history:
  - revision: 2
    at: "2026-10-31T18:40:45Z"
    checksum: sha256:bad8fcf0a118c3e70e905a37e2a675af537a501c6ee991994eff687210e2fe33
    summary: poc_available
    changed_fields:
      - claim_state
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=EF3BFD7B-F5FF-508B-A3DE-21AEC8A7FA82&utm_source=rss&utm_medium=rss
title: 'Gravity Forms: PHP object injection in Post Custom Fields (CVE-2026-103039)'
slug: 2026-10-gravity-forms-injection
description: Gravity Forms for WordPress versions up to and including 3.1.2 is vulnerable to unauthenticated PHP object injection via Post Custom Fields, which can lead to remote code execution when combined with specific gadget chains.
date: "2026-10-30T09:26:40Z"
lastmod: "2026-10-31T18:40:15Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:rocketgenius:gravity_forms:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=EF3BFD7B-F5FF-508B-A3DE-21AEC8A7FA82&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - deserialization
  - rce
vendors:
  - Rocketgenius
products:
  - Gravity Forms (<= 3.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject a PHP object into post meta.
    confidence_band: high
cves:
  - id: CVE-2026-103039
    cvss: 9.8
    epss: 0.00508
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103039
  - https://sploitus.com/exploit?id=EF3BFD7B-F5FF-508B-A3DE-21AEC8A7FA82&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Gravity Forms plugin to the latest version
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions up to 3.1.2
  hunt_leads:
    - lead: Search WordPress access logs for unusual POST requests targeting site-specific submission endpoints associated with Gravity Forms custom fields
      technique_id: T1190
      data_needed:
        - Web server access logs (POST method, request paths associated with Gravity Forms forms)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability occurs via a Post Custom Field whose input type is List.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Gravity Forms
      owner: IT Operations
      addresses: CVE-2026-103039
      evidence: Plugin version 3.1.2 and earlier are vulnerable
updates:
  - at: "2026-10-31T18:40:15Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=EF3BFD7B-F5FF-508B-A3DE-21AEC8A7FA82&utm_source=rss&utm_medium=rss
---

Gravity Forms versions 3.1.2 and earlier contain a PHP object injection vulnerability within the List input type of Post Custom Fields. The plugin incorrectly uses the native WordPress global `maybe_unserialize()` function instead of the secure `GFCommon::maybe_unserialize()` method. This allows unauthenticated attackers to supply serialized PHP objects. While the plugin contains no native gadget chains, exploitation is possible if other installed plugins, themes, or the WordPress core itself contain compatible gadgets. Notably, targeting the `_wp_page_template` meta key allows for RCE on environments where `register_argc_argv` is enabled and a PEAR installation is accessible.

## Impact
Successful exploitation allows unauthenticated attackers to perform remote code execution if a suitable gadget chain exists in the WordPress environment.

## Recommendation
- Update the Gravity Forms plugin to the latest version (patch released by Rocketgenius).
- Audit the WordPress site for plugins or themes that may contain dangerous deserialization gadget chains.
- Disable the `register_argc_argv` PHP configuration if not strictly required to mitigate the core-based gadget chain.
- Review custom field configurations to identify if they are mapped to sensitive meta keys like `_wp_page_template`.
