---
title: CVE-2026-18550 Privilege Escalation in Nokri Job Board WordPress Theme
slug: 2026-09-nokri-privilege-escalation
description: The Nokri Job Board WordPress theme is vulnerable to unauthenticated account takeover due to improper password reset token validation, allowing attackers to reset passwords for arbitrary user accounts.
date: "2026-09-01T13:05:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:nokri:job_board_wordpress_theme:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - vulnerability
  - privilege-escalation
vendors:
  - Nokri
products:
  - Nokri - Job Board WordPress Theme (<= 1.6.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: This makes it possible for unauthenticated attackers to reset the password of any user, including administrators, and gain access to their account.
    confidence_band: high
cves:
  - id: CVE-2026-18550
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18550
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit installed WordPress themes for Nokri Job Board and upgrade to version > 1.6.6.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18550 vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Disable vulnerable theme functionality or restrict public access to the password reset endpoint.
      owner: IT Operations
      addresses: CVE-2026-18550
      evidence: CVE-2026-18550 vulnerability description
---

The Nokri Job Board WordPress theme (versions 1.6.6 and earlier) contains a critical vulnerability (CVE-2026-18550) in its password reset mechanism. The flaw exists within the `nokri_reset_password()` function, which fails to adequately validate password reset tokens. An unauthenticated attacker can exploit this by providing an empty reset token in a crafted request. Due to the lack of validation, the empty token matches against users who have empty or unset `sb_password_forget_token` user meta values. This flaw enables attackers to bypass authentication and reset the password of any registered user, including site administrators. Successful exploitation leads to full account takeover and subsequent unauthorized access to the WordPress administrative dashboard.

## Impact

Successful exploitation of CVE-2026-18550 results in full account takeover, granting attackers complete administrative control over the affected WordPress site. This access can be leveraged to inject malicious content, exfiltrate sensitive data, or install persistent backdoors. Given the theme's function as a job board, affected sites may contain sensitive applicant and employer data.

## Recommendation

Prioritize the immediate update of the Nokri Job Board theme to a version later than 1.6.6 if available. If patching is not immediately possible, disable the theme's password reset functionality or implement server-side access controls to restrict access to the `nokri_reset_password` endpoint. Monitor web server access logs for anomalous POST requests targeting the password reset functionality.
