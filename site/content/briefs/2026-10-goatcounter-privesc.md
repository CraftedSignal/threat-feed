---
title: Privilege Escalation in GoatCounter via Mass Assignment
slug: 2026-10-goatcounter-privesc
description: GoatCounter versions 2.7.0 and earlier are vulnerable to a mass assignment flaw in the userPrefSave handler, enabling authenticated users to escalate privileges to administrator status.
date: "2026-10-11T14:01:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:goatcounter:goatcounter:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-vulnerability
vendors:
  - GoatCounter
products:
  - GoatCounter (<= 2.7.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated attacker can exploit this via form-encoded POST requests to modify protected account fields, such as 'user.access' or 'user.email_verified', allowing a low-privileged user to escalate their privileges to superuser or admin status.
    confidence_band: high
cves:
  - id: CVE-2026-108740
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108740
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade GoatCounter to version 2.7.1 or higher
      owner: IT Operations
      due: 48h
      evidence: Source identifies 2.7.0 as the last vulnerable version
  mitigation_plan:
    - priority: immediate
      action: Upgrade GoatCounter software to version 2.7.1+
      owner: IT Operations
      addresses: CVE-2026-108740
      evidence: NVD vulnerability notice
---

GoatCounter versions through 2.7.0 contain a mass assignment privilege escalation vulnerability located in the userPrefSave handler. This vulnerability arises from improper validation of form-encoded requests submitted to the /user/pref endpoint. Authenticated users with read-only access can exploit this flaw to overwrite protected account fields by including unauthorized keys in their POST requests. Specifically, by injecting parameters such as 'user.access[all]=*' and 'user.email_verified=true', a standard user can circumvent application logic and grant themselves superuser or administrative privileges. This vulnerability is critical for organizations relying on GoatCounter for internal analytics, as it allows unauthorized users to gain full control over the analytics dashboard and account settings.

## Impact

Successful exploitation allows a low-privileged authenticated user to gain full administrative control over the GoatCounter instance. This facilitates unauthorized access to potentially sensitive analytics data, modification of site configurations, and management of other user accounts within the environment.

## Recommendation

- Upgrade GoatCounter to a version greater than 2.7.0 immediately.
- Implement strict monitoring on the /user/pref endpoint for anomalous POST requests containing unexpected parameter structures, specifically those attempting to set access control fields.
- Audit existing administrative user accounts for unauthorized additions or unexpected changes to account permissions.
