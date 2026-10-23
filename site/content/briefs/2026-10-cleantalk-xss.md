---
brief_id: brief-2026-10-23-cleantalk-xss
event_id: brief-2026-10-23-cleantalk-xss
revision: 1
activity_at: "2026-10-23T06:47:11Z"
title: 'Anti-Spam by CleanTalk: Stored Cross-Site Scripting (CVE-2026-109198)'
slug: 2026-10-cleantalk-xss
description: The Anti-Spam by CleanTalk plugin for WordPress contains a stored cross-site scripting (XSS) vulnerability allowing unauthenticated attackers to execute arbitrary scripts in an administrator's browser session via the 'user_email' parameter.
date: "2026-10-23T06:47:11Z"
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
  validation_status: Verified against NVD metadata
cpes:
  - cpe:2.3:a:cleantalk:anti-spam_by_cleantalk:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
  - plugin-vulnerability
vendors:
  - CleanTalk
products:
  - Anti-Spam by CleanTalk – Spam Protection Without CAPTCHA (<= 6.89.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: script execution is triggered when an Administrator subsequently runs the plugin's user-spam scan and views the resulting Non-checkable users or Spam users tab
    confidence_band: high
cves:
  - id: CVE-2026-109198
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109198
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update Anti-Spam by CleanTalk plugin to version > 6.89.1
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability in versions <= 6.89.1
  mitigation_plan:
    - priority: immediate
      action: Disable user registration if not required, or update plugin
      owner: IT Operations
      addresses: CVE-2026-109198
      evidence: Exploitation requires user registration to be open on the site
---

The Anti-Spam by CleanTalk - Spam Protection Without CAPTCHA plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'user_email' parameter in versions 6.89.1 and earlier. Insufficient input sanitization and output escaping allow unauthenticated attackers to inject malicious scripts during the registration process. The script executes when an administrator views the plugin's 'Non-checkable users' or 'Spam users' tab.

## Attack Chain

1. Attacker identifies a WordPress site with the vulnerable CleanTalk plugin installed and user registration enabled.
2. Attacker submits a registration request using a malicious payload in the 'user_email' field.
3. The plugin fails to sanitize the malicious input and stores it in the WordPress database.
4. The plugin flags the registration as spam or 'non-checkable' based on its internal logic.
5. An administrator navigates to the plugin's dashboard to review the spam reports.
6. The plugin displays the list of spam users, causing the stored XSS payload to execute within the administrator's browser session.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript in the context of an administrator's browser session. This can lead to unauthorized actions performed on behalf of the administrator, such as creating new administrative accounts, modifying plugin settings, or redirecting site traffic.

## Recommendation

Update the "Anti-Spam by CleanTalk - Spam Protection Without CAPTCHA" plugin to the latest version available beyond 6.89.1. Ensure user registration settings are restricted to known users until a patch is applied if the plugin cannot be updated immediately.
