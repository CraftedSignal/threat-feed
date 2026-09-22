---
title: Unauthenticated Privilege Escalation in Meta Box AIO for WordPress
slug: 2026-09-meta-box-privilege-escalation
description: An unauthenticated privilege escalation vulnerability (CVE-2026-13355) in the Meta Box AIO plugin allows attackers to overwrite post content with arbitrary shortcodes to register administrative accounts.
date: "2026-09-22T06:33:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Meta Box
products:
  - Meta Box AIO (<= 3.11.0)
  - Meta Box Frontend Submission (<= 4.5.6)
  - Meta Box User Profile (<= 3.11.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Meta Box AIO plugin for WordPress is vulnerable to Privilege Escalation to Administrator in versions up to, and including, 3.11.0.
    confidence_band: high
cves:
  - id: CVE-2026-13355
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13355
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Meta Box AIO, Meta Box Frontend Submission, and Meta Box User Profile to versions post-dating 3.11.0 and 4.5.6.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies these versions as vulnerable.
  hunt_leads:
    - lead: Search WordPress post content for the presence of the [mb_user_profile_register] shortcode in public or sensitive pages.
      technique_id: T1068
      data_needed:
        - WordPress database table (wp_posts)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Injection of this shortcode is the identified mechanism for privilege escalation.
  mitigation_plan:
    - priority: immediate
      action: Patch Meta Box plugin suite to the latest vendor-provided versions.
      owner: IT Operations
      addresses: CVE-2026-13355
      evidence: NVD vulnerability disclosure.
---

The Meta Box AIO plugin for WordPress, along with its standalone components Meta Box Frontend Submission and Meta Box User Profile, is affected by a critical vulnerability (CVE-2026-13355) that enables unauthenticated privilege escalation to the Administrator role. The vulnerability exists due to a chained flaw between the mb-frontend-submission and mb-user-profile components. 

An attacker can exploit the 'populate_via_query_string()' function, which improperly processes the 'rwmb_frontend_field_object_id' GET parameter without authorization checks. This allows the attacker to overwrite the content of any post on the target WordPress site using 'wp_update_post()'. By injecting a malicious '[mb_user_profile_register]' shortcode into a post, the attacker leverages the mb-user-profile component's failure to validate the 'role' and 'auto_login' shortcode attributes. This process permits the registration or modification of user accounts, granting the attacker administrative access to the WordPress environment. This vulnerability affects Meta Box AIO versions up to 3.11.0, Meta Box Frontend Submission up to 4.5.6, and Meta Box User Profile up to 3.11.0.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative control over the affected WordPress installation. This can lead to unauthorized access to sensitive site data, modification of content, installation of malicious plugins or themes, and potential lateral movement into the hosting infrastructure.

## Recommendation

Prioritize the immediate update of the Meta Box AIO plugin, Meta Box Frontend Submission, and Meta Box User Profile to the latest patched versions released by the vendor. Conduct a forensic audit of posts and pages for unexpected shortcode injections, specifically looking for the '[mb_user_profile_register]' shortcode in posts modified after the plugin update threshold.
