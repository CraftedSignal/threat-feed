---
title: Privilege Escalation in Craft CMS via Registration Flaw
slug: 2026-09-02-craft-cms-privilege-escalation
description: Craft CMS versions prior to 5.10.11 contain a vulnerability allowing unauthenticated attackers to inherit administrator privileges by registering with the email address of a deactivated admin account when specific registration settings are active.
date: "2026-09-02T13:13:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:pixelandtonic:craft_cms:*:*:*:*:*:*:*:*
tags:
  - cve-2026-84795
  - privilege-escalation
  - cms
vendors:
  - Pixel & Tonic
products:
  - Craft CMS (< 5.10.11)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can register with a deactivated admin's email address to inherit administrator privileges when public registration and disabled email verification are configured.
    confidence_band: high
cves:
  - id: CVE-2026-84795
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84795
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Craft CMS to version 5.10.11 or later.
      owner: IT Operations
      due: 24h
      evidence: Source documentation for CVE-2026-84795 identifies 5.10.11 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Disable public registration and enable email verification in Craft CMS settings.
      owner: IT Operations
      addresses: CVE-2026-84795
      evidence: The vulnerability requires public registration and disabled email verification to be exploitable.
---

Craft CMS versions before 5.10.11 are vulnerable to an unauthorized privilege escalation flaw (CVE-2026-84795). The vulnerability arises because the system fails to correctly validate or clear the 'admin' flag when a user registers, specifically if they register with an email address previously associated with a deactivated administrator account. 

This issue is exploitable only under specific configuration scenarios: when public user registration is enabled and email verification is disabled. If these conditions are met, an attacker can register an account using the known email address of a deactivated admin. The application incorrectly maps the new registration to the existing, albeit deactivated, record's administrative privileges, resulting in full unauthorized access. This flaw represents a critical security risk as it bypasses standard access control mechanisms. Defenders must ensure that public registration is limited or strictly monitored and that email verification is enforced to prevent this vector.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative control over the Craft CMS instance. This can lead to total system compromise, unauthorized data exfiltration, and persistent access to the back-end administrative interface. This vulnerability affects all Craft CMS installations configured with public registration and disabled email verification running versions prior to 5.10.11.

## Recommendation

Prioritized actions for security teams:
- Update Craft CMS to version 5.10.11 or later immediately to address CVE-2026-84795.
- Review administrative account configurations to ensure that deactivated accounts are properly purged or restricted.
- Disable public user registration on all production Craft CMS instances unless explicitly required.
- Ensure that email verification is strictly enabled for all user registration flows to mitigate unauthorized account takeovers.
