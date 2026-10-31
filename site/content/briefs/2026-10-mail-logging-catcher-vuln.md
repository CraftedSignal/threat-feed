---
brief_id: brief-2026-10-31-mail-logging-catcher-vuln
event_id: brief-2026-10-31-mail-logging-catcher-vuln
revision: 1
activity_at: "2026-10-31T07:53:08Z"
title: 'Mail logging & Catcher: Sensitive Information Exposure (CVE-2026-120040)'
slug: 2026-10-mail-logging-catcher-vuln
description: The Mail logging & Catcher plugin for WordPress (<= 2.2.0) contains an information exposure vulnerability allowing authenticated users to extract password-reset keys and escalate privileges to administrator.
date: "2026-10-31T07:53:08Z"
type: advisory
types:
  - advisory
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
cpes:
  - cpe:2.3:a:mail_logging_&_catcher_project:mail_logging_&_catcher:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - privilege-escalation
  - web-application
vendors:
  - WordPress
products:
  - Mail logging & Catcher (<= 2.2.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers... to extract valid administrator password-reset keys... and complete the WordPress password-reset flow to escalate privileges to administrator.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: This makes it possible for authenticated attackers... to extract valid administrator password-reset keys from stored email logs
    confidence_band: high
cves:
  - id: CVE-2026-120040
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120040
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review all WordPress installations for the presence of Mail logging & Catcher plugin and audit current 'default_view_role' configurations.
      owner: IT Operations
      due: 48h
      evidence: Exploitation requires an administrator to have previously configured the plugin's default_view_role setting to a capability held by low-privileged users
  hunt_leads:
    - lead: Search WordPress access logs for repeated requests to the Mail logging & Catcher plugin endpoints by non-administrative accounts, specifically targeting the 'message' parameter.
      technique_id: T1530
      data_needed:
        - Web server access logs (Apache/Nginx/IIS)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: vulnerable... via the 'message' parameter.
  mitigation_plan:
    - priority: immediate
      action: Change the 'default_view_role' to 'manage_options' or restrict plugin access via .htaccess/web server rules until a patch is applied.
      owner: IT Operations
      addresses: CVE-2026-120040
      evidence: on an untouched install the default of 'manage_options' restricts log access to administrators only
---

CVE-2026-120040 affects the Mail logging & Catcher plugin for WordPress in all versions up to and including 2.2.0. The flaw resides in the 'message' parameter, which can leak sensitive data from stored email logs. Successful exploitation allows an authenticated user with at least subscriber-level access to access administrator password-reset keys, provided the 'default_view_role' setting has been configured to grant read access to low-privileged users. This can lead to unauthorized account takeover and privilege escalation to the administrator role.

## Impact

The vulnerability allows authenticated, low-privileged users to intercept administrator password-reset tokens. By successfully hijacking the password-reset flow, an attacker can gain full administrative control over the affected WordPress installation.

## Recommendation

* Update the Mail logging & Catcher plugin to the latest version once a patch is available.
* Audit the 'default_view_role' configuration within the plugin settings to ensure that access to email logs is restricted to the 'manage_options' capability or higher, preventing access by low-privileged user roles.
* Review WordPress audit logs for unusual password-reset activity initiated by non-administrative accounts.
