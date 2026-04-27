---
title: Sheed AntiVirus Unquoted Service Path Privilege Escalation (CVE-2016-20061)
slug: 2026-04-sheed-antivirus-privesc
description: Sheed AntiVirus 2.3 contains an unquoted service path vulnerability in the ShavProt service that allows local attackers to escalate privileges by placing a malicious executable in the unquoted path, leading to arbitrary code execution as LocalSystem.
date: "2026-04-04T14:16:18Z"
severities:
  - high
tags:
  - privilege-escalation
  - unquoted-service-path
  - cve-2016-20061
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
cves:
  - id: CVE-2016-20061
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20061
  - http://dl.sheedantivirus.ir/setup.exe
  - http://sheedantivirus.ir/
  - https://www.exploit-db.com/exploits/40497
  - https://www.vulncheck.com/advisories/sheed-antivirus-unquoted-service-path-privilege-escalation
ioc_counts:
  url: 4
rules:
  - title: Detect Suspicious Process Creation in Unquoted Path
    description: Detects process creation events where the executable path contains a space and is not enclosed in quotes, indicating a potential unquoted service path exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Detect sheed AntiVirus Download
    description: Detects downloads of the sheed AntiVirus setup executable from its official website.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Sheed AntiVirus 2.3 is vulnerable to an unquoted service path vulnerability (CVE-2016-20061) affecting the ShavProt service. This vulnerability, disclosed in April 2026, allows a local attacker with limited privileges to escalate their privileges to SYSTEM. The attack involves placing a malicious executable in a directory within the unquoted service path. When the ShavProt service starts (either through a service restart or system reboot), it attempts to execute binaries along the unquoted…
