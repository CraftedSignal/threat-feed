---
title: Twitch Studio Privilege Escalation Vulnerability (CVE-2024-14032)
slug: 2026-04-twitch-privesc
description: Twitch Studio version 0.114.8 and prior contains a privilege escalation vulnerability (CVE-2024-14032) that allows local attackers to execute arbitrary code as root by exploiting an unprotected XPC service, enabling them to overwrite system files and achieve full system compromise.
date: "2026-04-06T16:16:26Z"
severities:
  - critical
tags:
  - privilege-escalation
  - cve-2024-14032
  - twitch
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2024-14032
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-14032
  - https://www.vulncheck.com/advisories/twitch-studio-launcherhelper-xpc-missing-authorization-to-root-file-write
rules:
  - title: Detect Suspicious File Overwrite
    description: Detects potential exploitation of CVE-2024-14032 by monitoring for file overwrites in critical system directories by unexpected processes.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - macos
  - title: Detect Twitch Studio Helper Tool Execution
    description: Detects execution of Twitch Studio Helper Tool, which could be related to exploitation of CVE-2024-14032.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

Twitch Studio, specifically versions 0.114.8 and earlier, is vulnerable to a critical privilege escalation flaw (CVE-2024-14032). This vulnerability resides within the application's privileged helper tool and stems from an unprotected XPC service. A local attacker can exploit this vulnerability to execute arbitrary code with root privileges. The vulnerability allows the attacker to leverage the `installFromPath:toPath:withReply:` method to overwrite sensitive system files and privileged…
