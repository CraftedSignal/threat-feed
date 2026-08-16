---
title: PHP Object Injection in ARForms Plugin for WordPress
slug: 2026-08-arforms-php-injection
description: The ARForms WordPress plugin (up to v1.8.5) is vulnerable to unauthenticated PHP Object Injection, which may lead to remote code execution when combined with a POP chain in other installed software.
date: "2026-08-16T10:24:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin-vulnerability
  - php
  - deserialization
vendors:
  - Repute InfoSystems
products:
  - ARForms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject a PHP Object.
    confidence_band: high
cves:
  - id: CVE-2024-13784
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-13784
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch ARForms to version > 1.8.5
      owner: IT Operations
      due: 48h
      evidence: CVE-2024-13784 vulnerability remediation
---

The ARForms plugin (Contact Form, Survey, Quiz & Popup Form Builder) for WordPress contains a PHP Object Injection vulnerability in versions up to and including 1.8.5. The flaw originates from the insecure deserialization of untrusted input provided by users during form submissions. While the ARForms plugin itself does not include a POP chain, the vulnerability relies on the presence of a POP chain within other installed themes or plugins on the WordPress instance. If an attacker can leverage such a chain, they may perform unauthorized operations such as arbitrary file deletion, data exfiltration, or remote code execution. Because this vulnerability allows unauthenticated access to the deserialization process, it poses a high risk to WordPress environments that include common vulnerable plugins or complex themes.

## Impact

Successful exploitation depends on the availability of a POP chain within the target's environment. If triggered, impact includes complete site compromise through remote code execution, loss of sensitive database or configuration data, or service disruption via arbitrary file deletion. The vulnerability affects all users running ARForms 1.8.5 or older.

## Recommendation

* Update the ARForms plugin to the latest version immediately to remediate the insecure deserialization flaw.
* Audit installed plugins and themes to identify and remove software that contains known POP chain gadgets.
* Monitor web server logs for suspicious POST requests containing serialized PHP objects directed at endpoints associated with ARForms.
