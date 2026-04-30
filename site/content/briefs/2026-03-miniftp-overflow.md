---
title: MiniFtp Buffer Overflow Vulnerability (CVE-2019-25611)
slug: 2026-03-miniftp-overflow
description: MiniFtp contains a buffer overflow vulnerability in the parseconf_load_setting function allowing local attackers to execute arbitrary code by supplying oversized configuration values in the miniftpd.conf file.
date: "2026-03-23T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2019-25611
  - buffer-overflow
  - privilege-escalation
  - miniftp
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25611
  - https://github.com/skyqinsc/MiniFtp
  - https://www.exploit-db.com/exploits/46807
  - https://www.vulncheck.com/advisories/miniftp-parseconf-load-setting-buffer-overflow-via-configuration
rules:
  - title: Detect MiniFtp Configuration File Modification
    description: Detects modifications to the MiniFtp configuration file (miniftpd.conf), which could indicate a potential buffer overflow attack.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect MiniFtp Process Execution After Config Change
    description: Detects execution of the MiniFtp process shortly after a modification to its configuration file, potentially indicating exploitation of CVE-2019-25611.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The MiniFtp application is susceptible to a buffer overflow vulnerability, identified as CVE-2019-25611, within the `parseconf_load_setting` function. This flaw allows a local attacker to execute arbitrary code on the system. The vulnerability stems from insufficient bounds checking when loading configuration values from the `miniftpd.conf` file. By crafting a malicious configuration file with values exceeding 128 bytes, an attacker can overflow stack buffers, overwrite the return address, and…
