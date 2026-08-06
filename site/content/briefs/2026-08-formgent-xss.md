---
title: Stored XSS Vulnerability in FormGent WordPress Plugin
slug: 2026-08-formgent-xss
description: An unauthenticated stored cross-site scripting vulnerability in FormGent versions 1.9.2 and below allows attackers to inject malicious scripts into form fields that execute upon viewing.
date: "2026-08-06T13:23:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - wordpress
  - xss
vendors:
  - wpwax
products:
  - FormGent – Next-Gen AI Form Builder for WordPress with Multi-Step, Quizzes, Payments & More (1.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The FormGent plugin is vulnerable to Stored Cross-Site Scripting via form submission fields.
    confidence_band: high
cves:
  - id: CVE-2025-15028
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-15028
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/d774af46-4928-4e86-b0e0-1a73f39a8f09?source=cve
rules:
  - title: Detects CVE-2025-15028 Exploitation - Stored XSS Attempt
    description: Detects attempts to inject script tags through HTTP POST requests typically associated with form submissions in WordPress plugins.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update FormGent plugin to the latest version to address CVE-2025-15028
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability in all versions up to 1.9.2
  mitigation_plan:
    - priority: immediate
      action: Enable WAF rules to sanitize or block input containing HTML tags for form-submitting endpoints
      owner: IT Operations
      addresses: CVE-2025-15028
      evidence: NVD vulnerability details regarding input sanitization
---

The FormGent AI Form Builder plugin for WordPress (versions 1.9.2 and below) contains a critical stored cross-site scripting (XSS) vulnerability. The flaw exists due to insufficient sanitization of user-supplied data within form submission fields. Because the plugin fails to properly escape input before rendering it on administrative or public-facing pages, an unauthenticated attacker can submit malicious JavaScript payloads through the plugin's forms. Once submitted, these scripts are stored in the WordPress database and automatically execute in the browser context of any user, including administrators, who subsequently accesses the page where the form entries are displayed. This vulnerability poses a significant risk for account takeover, session theft, and unauthorized actions within the WordPress environment.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to perform actions on behalf of privileged users, including administrators. This can lead to full site compromise, unauthorized administrative actions, redirection of users to malicious domains, or the theft of sensitive session cookies. Organizations utilizing this plugin for public-facing forms are at high risk of exploitation from external threats.

## Recommendation

Prioritized actions for security teams:
- Update the FormGent plugin to the latest version (v1.9.3 or higher) immediately to ensure proper input sanitization is applied.
- Review WordPress administrative logs for suspicious modifications performed by non-administrator accounts.
- Deploy the WAF rule below to detect and block malicious script injection attempts targeting the plugin's submission endpoint.
