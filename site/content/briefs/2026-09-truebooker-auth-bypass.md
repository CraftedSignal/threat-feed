---
title: Authorization Bypass in TrueBooker WordPress Plugin
slug: 2026-09-truebooker-auth-bypass
description: The TrueBooker Appointment Booking and Scheduler System plugin for WordPress contains an authorization bypass vulnerability allowing unauthenticated attackers to modify arbitrary user email addresses and facilitate account takeover.
date: "2026-09-16T05:46:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:truebooker_project:truebooker:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - authorization-bypass
vendors:
  - WordPress
products:
  - TrueBooker – Appointment Booking and Scheduler System (<= 1.2.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The TrueBooker – Appointment Booking and Scheduler System plugin for WordPress is vulnerable to authorization bypass.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This can be chained to initiate a password reset and gain unauthorized account access.
    confidence_band: high
cves:
  - id: CVE-2026-14349
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14349
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory and patch all WordPress sites running TrueBooker plugin
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-14349 documentation
  mitigation_plan:
    - priority: immediate
      action: Remove or disable plugin until a vendor-supplied patch is installed
      owner: IT Operations
      addresses: CVE-2026-14349
      evidence: Source advisory
---

The TrueBooker - Appointment Booking and Scheduler System plugin for WordPress is vulnerable to an authorization bypass flaw (CVE-2026-14349) affecting all versions up to and including 1.2.3. The vulnerability stems from a failure to perform adequate authorization checks on critical administrative functions. An unauthenticated attacker can exploit this flaw to update the email address associated with any user account, including those with administrator privileges. By redirecting the administrative email address to an attacker-controlled account, the adversary can initiate a standard WordPress password reset request. This mechanism allows the attacker to hijack administrative sessions, potentially leading to full site compromise, data exfiltration, and the deployment of persistent backdoors within the WordPress environment. This vulnerability is highly severe given its ease of exploitation and the direct path to privilege escalation.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative control over the affected WordPress installation. This can result in complete site compromise, unauthorized access to sensitive booking data, customer information exfiltration, and the installation of malicious software or redirect scripts. The vulnerability impacts any organization relying on the TrueBooker plugin for scheduling, regardless of their specific industry.

## Recommendation

1. Identify all WordPress installations utilizing the TrueBooker plugin.
2. Immediate remediation: Update the TrueBooker - Appointment Booking and Scheduler System plugin to the latest version as soon as a patch is released by the developer.
3. If a patch is unavailable, deactivate or remove the plugin until a secure version is confirmed.
4. Conduct an audit of administrative user accounts for unauthorized email changes or suspicious activity log entries.
5. Implement web application firewall (WAF) rules to restrict access to administrative API endpoints associated with user profile modification.
