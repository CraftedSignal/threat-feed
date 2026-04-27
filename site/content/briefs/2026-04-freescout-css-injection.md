---
title: FreeScout CSS Injection Vulnerability in Mailbox Signature Leads to Privilege Escalation (CVE-2026-40497)
slug: 2026-04-freescout-css-injection
description: FreeScout versions prior to 1.8.213 are vulnerable to CSS injection via the mailbox signature, allowing an attacker with mailbox settings access to exfiltrate CSRF tokens and escalate privileges.
date: "2026-04-21T03:16:08Z"
severities:
  - high
tags:
  - freescout
  - css-injection
  - privilege-escalation
  - cve-2026-40497
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40497
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40497
rules:
  - title: FreeScout Suspicious Mailbox Signature Update
    description: Detects suspicious updates to the FreeScout mailbox signature field potentially containing CSS injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: FreeScout Mailbox Settings Access
    description: Detects access to the mailbox settings page, which could be a precursor to exploiting CVE-2026-40497.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout, a self-hosted help desk and shared mailbox platform, is susceptible to a CSS injection vulnerability (CVE-2026-40497) in versions prior to 1.8.213. The vulnerability resides within the `Helper::stripDangerousTags()` function, which inadequately sanitizes the mailbox signature field. While the function removes `<script>`, `<form>`, `<iframe>`, and `<object>` tags, it fails to strip `<style>` tags. An attacker with access to mailbox settings, either an administrator or an agent with…
