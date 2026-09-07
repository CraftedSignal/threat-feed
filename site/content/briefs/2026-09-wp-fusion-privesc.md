---
title: Privilege Escalation Vulnerability in WP Fusion (Pro) WordPress Plugin
slug: 2026-09-wp-fusion-privesc
description: The WP Fusion (Pro) plugin is vulnerable to unauthorized administrator account creation due to insufficient authorization checks in the ThriveCart Auto Login handler, allowing authenticated users to escalate privileges.
date: "2026-09-07T15:33:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp_fusion:wp_fusion:*:*:*:*:pro:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - web-application
vendors:
  - WP Fusion
products:
  - WP Fusion (Pro) (<= 3.47.13)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, and who possess the access_key, to create a new user account with administrator privileges and gain full control over the WordPress site.
    confidence_band: high
cves:
  - id: CVE-2026-14444
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14444
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade WP Fusion (Pro) to version 3.47.14 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-14444 advisory
  mitigation_plan:
    - priority: immediate
      action: Disable ThriveCart Auto Login in plugin settings
      owner: IT Operations
      addresses: CVE-2026-14444
      evidence: The vulnerability is only exploitable when the ThriveCart Auto Login option is enabled.
---

The WP Fusion (Pro) plugin for WordPress is vulnerable to a privilege escalation flaw (CVE-2026-14444) affecting all versions up to and including 3.47.13. The vulnerability exists within the ThriveCart Auto Login handler's thrivecart() function, which fails to adequately validate authorization when processing the role parameter. 

To exploit this, an attacker must have at least Subscriber-level access on the target WordPress site. The attack requires the attacker to possess the access_key associated with the site's ThriveCart integration, which is typically shared during the plugin's documented setup process. When the ThriveCart Auto Login feature is enabled, an attacker can manipulate the request to create a new user account with administrator privileges. This flaw poses a significant risk to the integrity of affected WordPress installations, as it grants full administrative control to unauthorized parties who have access to the shared integration key.

## Impact

Successful exploitation allows an authenticated Subscriber to escalate their privileges to Administrator, resulting in full site compromise. This can lead to total loss of control over the WordPress environment, including unauthorized data access, malicious plugin installation, and potential site-wide persistence.

## Recommendation

- Upgrade the WP Fusion (Pro) plugin to a version newer than 3.47.13 immediately.
- Disable the ThriveCart Auto Login feature if it is not actively required for business operations.
- Audit existing administrator accounts to identify any unauthorized users created while the vulnerable version was active.
- Rotate the ThriveCart access_key if there is any suspicion of unauthorized access or exposure of the integration credentials.
