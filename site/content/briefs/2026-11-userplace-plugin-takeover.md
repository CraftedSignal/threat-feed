---
brief_id: brief-2026-11-08-userplace-plugin-takeover
event_id: brief-2026-11-08-userplace-plugin-takeover
revision: 1
activity_at: "2026-11-08T21:28:26Z"
title: 'Userplace WordPress plugin: Unauthenticated administrative account creation (CVE-2026-110963)'
slug: 2026-11-userplace-plugin-takeover
description: The Userplace WordPress plugin through 1.2.0 fails to perform authorization checks on an exposed AJAX action, allowing unauthenticated attackers to create administrator accounts and modify site settings for full site takeover.
date: "2026-11-08T21:28:26Z"
type: advisory
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:userplace:userplace:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - wordpress
  - cve-2026-110963
  - authorization-bypass
vendors:
  - Userplace
products:
  - Userplace (<= 1.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Userplace WordPress plugin through 1.2.0 does not perform authorization checks on an AJAX action available to unauthenticated users
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.001
    technique_name: Local Account
    evidence: allowing unauthenticated attackers to create an administrator account
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allowing unauthenticated attackers to create an administrator account... leading to full site takeover
    confidence_band: high
cves:
  - id: CVE-2026-110963
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110963
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all WordPress instances utilizing the Userplace plugin version 1.2.0 or below
      owner: IT Operations
      due: 24h
      evidence: Vulnerability confirmed in Userplace version 1.2.0 and earlier
  hunt_leads:
    - lead: Search web server logs for HTTP POST requests to the plugin AJAX endpoint containing parameter changes consistent with account creation or site option modification
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability involves unauthorized AJAX actions leading to account creation or option changes
  mitigation_plan:
    - priority: immediate
      action: Disable or uninstall the Userplace plugin
      owner: IT Operations
      addresses: CVE-2026-110963
      evidence: Plugin through 1.2.0 is vulnerable
---

The Userplace WordPress plugin through 1.2.0 contains an authorization bypass vulnerability. An AJAX action, intended to be restricted, is accessible to unauthenticated users. The plugin also publicly exposes the nonce meant to protect this action. An attacker can use these flaws to inject administrative credentials or alter critical site configuration options, resulting in a full site takeover.

## Impact

Successful exploitation allows unauthenticated attackers to perform administrative actions, including the creation of new administrator accounts and the modification of arbitrary WordPress site options.

## Recommendation

- Audit WordPress installations for the presence of the Userplace plugin version 1.2.0 or earlier.
- Disable or remove the Userplace plugin until a vendor-supplied patch is installed.
- Review the WordPress 'wp_users' and 'wp_options' tables for unauthorized administrative accounts or suspicious configuration changes created after November 8, 2026.
