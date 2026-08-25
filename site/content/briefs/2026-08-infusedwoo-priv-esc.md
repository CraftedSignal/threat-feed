---
title: Privilege Escalation in InfusedWoo Pro WordPress Plugin
slug: 2026-08-infusedwoo-priv-esc
description: The InfusedWoo Pro plugin for WordPress, in versions up to 5.1.17, contains a privilege escalation vulnerability allowing authenticated subscribers to perform unauthorized password resets for arbitrary accounts via the ajax_iwar_preview_email function.
date: "2026-08-25T06:05:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - privilege-escalation
  - web-application
vendors:
  - InfusedWoo
products:
  - InfusedWoo Pro
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated attacker with subscriber-level access can leverage this flaw to generate and retrieve password reset links for arbitrary users, including administrators, leading to full account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-19892
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19892
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update InfusedWoo Pro plugin to version 5.1.18 or higher.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability CVE-2026-19892 affects versions <= 5.1.17.
  mitigation_plan:
    - priority: immediate
      action: Review administrative accounts for suspicious password resets.
      owner: SOC
      addresses: CVE-2026-19892
      evidence: Vulnerability allows password reset link interception.
---

The InfusedWoo Pro plugin for WordPress contains a critical privilege escalation vulnerability (CVE-2026-19892) affecting all versions up to and including 5.1.17. The vulnerability exists within the `ajax_iwar_preview_email()` function, which fails to implement appropriate capability checks, relying solely on an insufficient `is_admin()` check. This allows an authenticated user with low-level privileges, such as a subscriber, to interact with the function to render email preview merge fields for arbitrary users. By manipulating the parameters, an attacker can trigger and retrieve password reset tokens or links intended for other users, including administrators, effectively granting the attacker full account takeover capabilities. This flaw represents a significant risk to WordPress site integrity as it circumvents standard authorization flows.

## Impact

Successful exploitation allows an authenticated subscriber to escalate their privileges to any account level on the WordPress site, including administrative access. This bypass enables unauthorized data access, site configuration changes, and potentially full server compromise depending on the WordPress environment and plugin integrations.

## Recommendation

- Upgrade the InfusedWoo Pro plugin to a version beyond 5.1.17 immediately.
- Monitor web server access logs for anomalous POST requests targeting the `admin-ajax.php` endpoint associated with the InfusedWoo plugin parameters.
- Audit user privilege assignments and recent password reset activity for administrative accounts to identify potential signs of unauthorized access.
