---
title: OpenClaw Privilege Escalation via Telegram Configuration and Cron Persistence Settings
slug: 2026-04-openclaw-privesc
description: OpenClaw before 2026.3.28 contains a privilege escalation vulnerability that allows authenticated operators with write permissions to access and modify admin-class Telegram configuration and cron persistence settings via the send endpoint.
date: "2026-04-24T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - persistence
  - cve-2026-41359
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053.003
    technique_name: 'Scheduled Task/Job: Cron'
cves:
  - id: CVE-2026-41359
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41359
  - https://github.com/openclaw/openclaw/commit/b7d70ade3b9900dbe97bd73be9c02e924ff3c986
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-767m-xrhc-fxm7
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-operator-write-to-admin-class-telegram-config-and-cron-persistence
rules:
  - title: Detect OpenClaw Cron Persistence Modification
    description: Detects unauthorized modification of cron jobs, potentially indicating privilege escalation via CVE-2026-41359.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1053.003
    data_sources:
      - file_event
      - linux
  - title: Detect OpenClaw Telegram Configuration Modification
    description: Detects unauthorized modification of telegram configuration, potentially indicating privilege escalation via CVE-2026-41359.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw, in versions prior to 2026.3.28, is vulnerable to a privilege escalation. An authenticated operator with `operator.write` credentials can leverage this vulnerability to access sensitive administrative functions. Specifically, the flaw resides in the `send` endpoint where insufficient access controls allow unauthorized modification of Telegram configurations and cron persistence settings, which are typically restricted to admin-level users. Successful exploitation allows an attacker to…
