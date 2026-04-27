---
title: FreeScout Privilege Escalation via Email Address Reassignment (CVE-2026-40589)
slug: 2026-04-freescout-privesc
description: FreeScout versions before 1.8.214 are vulnerable to privilege escalation, allowing a low-privileged agent to reassign email addresses from hidden customers to visible customers, leading to information disclosure and unauthorized access to conversations.
date: "2026-04-22T12:00:00Z"
severities:
  - medium
tags:
  - privilege-escalation
  - cve-2026-40589
  - freescout
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40589
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40589
  - https://github.com/freescout-help-desk/freescout/commit/2e2fe37111d92ac665b9ad8806eac94a1a3e502c
  - https://github.com/freescout-help-desk/freescout/releases/tag/1.8.214
  - https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-mv55-3mgv-fxwr
ioc_counts:
  email: 1
rules:
  - title: FreeScout Hidden Customer Data Disclosure
    description: Detects potential attempts to exploit CVE-2026-40589 by monitoring web server logs for requests that may lead to hidden customer data disclosure in FreeScout.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: FreeScout Suspicious Email Reassignment
    description: Detects suspicious email reassignment attempts in FreeScout by monitoring for specific patterns in web server logs.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout is a self-hosted help desk and shared mailbox system. A critical vulnerability, identified as CVE-2026-40589, exists in versions prior to 1.8.214. This flaw allows a low-privileged agent to escalate their privileges by manipulating customer records. Specifically, an agent can edit a visible customer's profile and add an email address that is already associated with a hidden customer in a different mailbox. This results in the disclosure of the hidden customer's name and profile URL…
