---
title: Privilege Escalation Vulnerability in Aimogen Pro WordPress Plugin
slug: 2026-07-aimogen-pro-privilege-escalation
description: A critical privilege escalation vulnerability, CVE-2026-15982, exists in the Aimogen Pro - All-in-One AI Content Writer, Editor, ChatBot & Automation Toolkit WordPress plugin, affecting versions up to and including 2.8.4, allowing unauthenticated attackers to leverage the 'aimogen_wp_god_mode' tool to clear function blacklists, execute arbitrary PHP functions, and create administrator accounts, leading to full compromise of the WordPress site.
date: "2026-07-17T06:18:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web
  - wordpress
  - plugin
  - privilege-escalation
  - cve
vendors:
  - Aimogen
  - WordPress
products:
  - Aimogen Pro - All-in-One AI Content Writer, Editor, ChatBot & Automation Toolkit plugin (< 2.8.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute arbitrary PHP functions
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: creating administrator accounts
    confidence_band: high
cves:
  - id: CVE-2026-15982
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15982
---

A critical privilege escalation vulnerability, tracked as CVE-2026-15982, has been identified in the Aimogen Pro - All-in-One AI Content Writer, Editor, ChatBot & Automation Toolkit plugin for WordPress, affecting all versions up to and including 2.8.4. This flaw is due to a missing capability check on the `aiomatic_call_google_ai_function`. Exploiting this, unauthenticated attackers can leverage the `aimogen_wp_god_mode` tool. This tool, when misused, allows attackers to bypass internal function blacklists and execute arbitrary PHP functions. The ultimate objective of such an attack is typically to create new administrator accounts on the affected WordPress site, granting the attacker full control over the website's content, data, and settings. This vulnerability poses a significant risk to affected WordPress installations, potentially leading to website defacement, data theft, and further malicious activity.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site running a vulnerable version of the Aimogen Pro plugin (up to 2.8.4).
2. The attacker crafts a malicious HTTP request targeting the `aiomatic_call_google_ai_function` endpoint, which is accessible due to the missing capability check.
3. The request is designed to exploit this missing check, allowing the attacker to call and leverage the `aimogen_wp_god_mode` tool.
4. Using the `aimogen_wp_god_mode` tool, the attacker clears internal function blacklists, removing restrictions on which PHP functions can be executed.
5. The attacker then executes arbitrary PHP functions on the server.
6. A specific PHP function call is used to create a new administrator account within the WordPress installation.
7. With the newly created administrator account, the attacker gains full control over the WordPress site, enabling further malicious actions.

## Impact

The successful exploitation of CVE-2026-15982 grants an unauthenticated attacker full administrator privileges on the targeted WordPress site. This leads to complete compromise of the website, allowing for actions such as website defacement, content modification, data exfiltration, injection of malicious code (e.g., malware, spam, phishing pages), and unauthorized redirection of traffic. The integrity and availability of the affected website are severely compromised, potentially leading to reputational damage, financial losses, and regulatory penalties. There is no specific information on the number of victims or sectors targeted, but any WordPress site running the vulnerable plugin is at risk.

## Recommendation

* Patch CVE-2026-15982 immediately by updating the Aimogen Pro - All-in-One AI Content Writer, Editor, ChatBot & Automation Toolkit plugin to version 2.8.5 or higher.
* Regularly review WordPress user accounts for any newly created or suspicious administrator accounts.
