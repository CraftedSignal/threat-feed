---
title: Stored Cross-Site Scripting in Ninja Forms Plugin
slug: 2026-09-ninja-forms-xss
description: CVE-2026-94504 describes a stored cross-site scripting vulnerability in Ninja Forms version 3.15.3, allowing attackers to execute arbitrary scripts in an administrator's browser session via the legacy submission editor.
date: "2026-09-22T08:34:19Z"
lastmod: "2026-09-24T04:07:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ninja_forms:ninja_forms:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=34ADA71A-08D7-59AD-8BE3-8926666DB8A2&utm_source=rss&utm_medium=rss
tags:
  - xss
  - web-vulnerability
  - wordpress
vendors:
  - Ninja Forms
products:
  - Ninja Forms (<= 3.15.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: The legacy submission editor fails to properly encode non-RTE textarea values, allowing an attacker to inject malicious scripts.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: When an Administrator opens the attacker-known direct submission URL, the script runs in the WordPress admin origin.
    confidence_band: high
cves:
  - id: CVE-2026-94504
    cvss: 7.2
    epss: 0.00292
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94504
  - https://sploitus.com/exploit?id=34ADA71A-08D7-59AD-8BE3-8926666DB8A2&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Ninja Forms to version 3.15.4 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-94504
  hunt_leads:
    - lead: Search WordPress submission database logs for textarea fields containing script tags or event handlers (e.g., <script>, onerror, onload)
      technique_id: T1203
      data_needed:
        - Web server access logs
        - Application database records
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Stored XSS via textarea inputs
updates:
  - at: "2026-09-24T04:07:30Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=34ADA71A-08D7-59AD-8BE3-8926666DB8A2&utm_source=rss&utm_medium=rss
---

CVE-2026-94504 is a security vulnerability in the Ninja Forms plugin (version 3.15.3) that stems from improper input sanitization of anonymous non-RTE (Rich Text Editor) textarea fields. The plugin stores user-provided input in these fields and fails to perform adequate HTML encoding when rendering the data within the legacy submission editor interface. An attacker can supply malicious JavaScript payloads within these textarea inputs. When a site administrator accesses the specific direct submission URL associated with the malicious entry, the injected script executes within the context of the WordPress admin origin. This flaw allows attackers to perform unauthorized actions or gain access to sensitive information by leveraging the trust associated with the administrator's authenticated session.

## Impact

Successful exploitation results in Stored Cross-Site Scripting (XSS), which can lead to session hijacking, unauthorized administrative actions, or the unauthorized modification of site content. This vulnerability specifically impacts WordPress environments where Ninja Forms 3.15.3 is installed and utilizes the legacy submission editor.

## Recommendation

1. Upgrade the Ninja Forms plugin to a patched version beyond 3.15.3 immediately.
2. Implement a strong Content Security Policy (CSP) to mitigate the execution of unauthorized scripts in the WordPress admin dashboard.
3. Audit existing submission entries for suspicious script tags or obfuscated JavaScript payloads.
