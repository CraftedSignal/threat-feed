---
title: Privilege Escalation in JetFormBuilder Plugin for WordPress
slug: 2026-09-jetformbuilder-privesc
description: An unauthenticated privilege escalation vulnerability (CVE-2026-12793) in the JetFormBuilder plugin allows attackers to register arbitrary administrator accounts via improper server-side validation.
date: "2026-09-16T05:46:20Z"
lastmod: "2026-09-16T16:56:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:jetformbuilder:dynamic_blocks_form_builder:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0C977A49-52F9-5070-AD85-782B6DDFFD63&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - web-application
vendors:
  - JetFormBuilder
products:
  - Dynamic Blocks Form Builder (<= 3.6.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to create a new administrator-level user account.
    confidence_band: high
cves:
  - id: CVE-2026-12793
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12793
  - https://sploitus.com/exploit?id=0C977A49-52F9-5070-AD85-782B6DDFFD63&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade JetFormBuilder to a version beyond 3.6.2
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-12793
  hunt_leads:
    - lead: Search WordPress user audit logs for new administrative accounts created by unknown or unauthenticated users
      technique_id: T1068
      data_needed:
        - WordPress authentication and user management logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Plugin allows unauthenticated creation of administrator accounts
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest version of JetFormBuilder
      owner: IT Operations
      addresses: CVE-2026-12793
      evidence: NVD advisory for CVE-2026-12793
updates:
  - at: "2026-09-16T16:56:06Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0C977A49-52F9-5070-AD85-782B6DDFFD63&utm_source=rss&utm_medium=rss
---

The JetFormBuilder - Dynamic Blocks Form Builder plugin for WordPress is affected by a critical privilege escalation vulnerability, assigned CVE-2026-12793. The vulnerability exists in versions up to and including 3.6.2. The security flaw stems from a lack of server-side validation concerning submitted form IDs. Specifically, the plugin fails to verify if a provided form ID is legitimate before parsing the referenced post's content as a form schema. This oversight enables the execution of an Advanced Validation server-side callback using attacker-controlled input. An unauthenticated attacker can exploit this mechanism to facilitate the creation of an administrative-level user account on the WordPress site. Given the plugin's functionality, this flaw represents a significant risk to site integrity and control.

## Impact

Successful exploitation results in full administrative control over the affected WordPress instance. Attackers can create unauthorized administrator accounts, leading to complete site compromise, data exfiltration, and the deployment of further malicious persistence mechanisms. This vulnerability affects all WordPress installations utilizing the JetFormBuilder plugin version 3.6.2 or earlier.

## Recommendation

- Upgrade the JetFormBuilder - Dynamic Blocks Form Builder plugin to the latest version immediately to remediate CVE-2026-12793.
- Audit existing WordPress user accounts for suspicious administrative privileges created after the discovery of this vulnerability.
- Restrict access to WordPress administrative endpoints and plugin configuration interfaces to authorized networks where possible.
