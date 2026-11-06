---
brief_id: brief-2026-11-06-acf-privilege-escalation
event_id: brief-2026-11-06-acf-privilege-escalation
revision: 1
activity_at: "2026-11-06T13:11:59Z"
title: 'Advanced Members for ACF: Privilege Escalation via Password Overwrite (CVE-2026-116624)'
slug: 2026-11-acf-privilege-escalation
description: An authenticated attacker can escalate privileges to administrator by exploiting a logical error in the Advanced Members for ACF WordPress plugin to overwrite the administrator password.
date: "2026-11-06T13:11:59Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Plugin vulnerability confirmed via NVD; requires environment validation to check for plugin presence
cpes:
  - cpe:2.3:a:advanced_members_for_acf_project:advanced_members_for_acf:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - web-vulnerability
vendors:
  - WordPress
products:
  - Advanced Members for ACF (<= 1.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to overwrite the password of user ID 1 (the site is primary administrator) with an attacker-chosen value, granting full administrative access to the site.
    confidence_band: high
cves:
  - id: CVE-2026-116624
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116624
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify WordPress instances running Advanced Members for ACF plugin
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects all versions up to and including 1.3.0
  hunt_leads:
    - lead: Identify authenticated form submissions to the shortcode path that result in user account updates
      technique_id: T1068
      data_needed:
        - Web server access logs
        - WordPress plugin activity logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves submitting the acf[_amem_local_user_password] parameter
  mitigation_plan:
    - priority: immediate
      action: Upgrade Advanced Members for ACF to a patched version
      owner: IT Operations
      addresses: CVE-2026-116624
      evidence: Vulnerable in all versions up to 1.3.0
---

The Advanced Members for ACF WordPress plugin (versions 1.3.0 and below) is vulnerable to privilege escalation via the [advanced-members-account-password] shortcode. An operator-precedence bug in the pre_update_value function within acf/fields/class-user-password.php causes the system to incorrectly authorize password updates by defaulting the $user_id to boolean true, which evaluates to ID 1 via PHP loose equality. Additionally, a flaw in the amem_save_all_fields function fails to respect field exclusion guards, allowing the password update to proceed even if the application expects it to be blocked.

## Attack Chain

1. Attacker authenticates to a WordPress site as a user with at least Subscriber-level access.
2. Attacker navigates to a page containing the [advanced-members-account-password] shortcode.
3. Attacker submits the form containing the acf[_amem_local_user_password] parameter.
4. The plugin's pre_update_value function processes the request and hits the PHP operator-precedence bug.
5. The authorization logic incorrectly evaluates $user_id as boolean true, bypassing the _can_edit() check.
6. The system executes wp_update_user(), targeting user ID 1 due to type casting of the boolean ID.
7. The amem_save_all_fields function overrides the exclusion guard, ensuring the malicious password change is processed.
8. The administrator account password is overwritten with the attacker-provided value, granting full administrative access.

## Impact

Authenticated users with low-level privileges can gain full administrative access to the WordPress site, leading to potential data exfiltration, site defacement, or total system compromise.

## Recommendation

- Identify all WordPress sites utilizing the Advanced Members for ACF plugin.
- Update to a version beyond 1.3.0 immediately when a patch becomes available.
- Disable the [advanced-members-account-password] shortcode or restrict access to administrative-only pages until a patch is applied.
- Audit user management logs for unexpected password change events for administrator accounts.
