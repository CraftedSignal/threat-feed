---
title: Authorization Bypass in Master Addons for Elementor
slug: 2026-09-master-addons-bypass
description: An authorization bypass vulnerability in the Master Addons for Elementor WordPress plugin allows authenticated contributors to modify or delete arbitrary posts.
date: "2026-09-18T10:06:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:master_addons:master_addons_for_elementor:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - authorization-bypass
vendors:
  - Master Addons
products:
  - Master Addons for Elementor (<= 3.2.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with contributor-level access and above, to modify the title and metadata of arbitrary WordPress posts or permanently delete arbitrary WordPress posts by supplying an attacker-controlled popup_id.
    confidence_band: high
cves:
  - id: CVE-2026-85410
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85410
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Master Addons for Elementor to version 3.2.3 or later.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 3.2.2
  mitigation_plan:
    - priority: immediate
      action: Upgrade Master Addons for Elementor to latest patched version.
      owner: IT Operations
      addresses: CVE-2026-85410
      evidence: Plugin vulnerable in versions <= 3.2.2
---

The Master Addons for Elementor plugin for WordPress is vulnerable to an authorization bypass flaw, tracked as CVE-2026-85410, affecting all versions up to and including 3.2.2. The vulnerability stems from improper capability verification when handling the jltma_popup custom post type. Because this post type is registered with 'capability_type' set to 'post', WordPress grants contributor-level users access to the associated admin screen. This screen exposes a nonce required to execute administrative actions. Attackers with contributor access can leverage this exposed nonce to bypass authorization controls, allowing them to modify the title and metadata of arbitrary posts or permanently delete posts by supplying an attacker-controlled 'popup_id' parameter to the plugin's backend endpoints.

## Impact

Successful exploitation allows authenticated users with contributor-level permissions to escalate their capabilities to delete or modify any post on the affected WordPress site, potentially leading to unauthorized data modification, defacement, or total loss of content. This impact is significant for sites with multiple contributors or where contributor accounts may be compromised.

## Recommendation

1. Patch immediately by upgrading the Master Addons for Elementor plugin to a version beyond 3.2.2.
2. Audit user accounts with contributor-level access to identify potentially unauthorized activity or compromise.
3. Review web server access logs for anomalous POST requests targeting the plugin's administrative endpoints associated with 'jltma_popup' actions from contributor accounts.
