---
title: VA MAX 8.3.4 Remote Code Execution via changeip.php (CVE-2019-25671)
slug: 2026-04-va-max-rce
description: VA MAX 8.3.4 is vulnerable to remote code execution (CVE-2019-25671), allowing authenticated attackers to execute arbitrary commands by injecting shell metacharacters into the mtu_eth0 parameter via a POST request to changeip.php.
date: "2026-04-05T21:16:44Z"
severities:
  - critical
tags:
  - rce
  - cve-2019-25671
  - web-application
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2019-25671
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25671
  - https://www.exploit-db.com/exploits/46348
  - https://www.vulncheck.com/advisories/va-max-remote-code-execution-via-changeip-php
ioc_counts:
  url: 2
rules:
  - title: Detect RCE attempt via changeip.php
    description: Detects attempts to exploit CVE-2019-25671 by injecting shell metacharacters into the mtu_eth0 parameter in a POST request to changeip.php
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Processes Spawned by Apache
    description: Detects suspicious processes spawned by the Apache web server, potentially indicating command execution via CVE-2019-25671
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

VA MAX 8.3.4 is susceptible to a remote code execution (RCE) vulnerability identified as CVE-2019-25671. This vulnerability allows authenticated attackers to inject shell metacharacters into the `mtu_eth0` parameter, leading to arbitrary command execution. The attack vector involves sending crafted POST requests to the `changeip.php` endpoint. Successful exploitation grants the attacker the ability to execute commands as the `apache` user. This vulnerability poses a significant risk to…
