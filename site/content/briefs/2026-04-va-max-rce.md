---
title: VA MAX 8.3.4 Remote Code Execution via changeip.php (CVE-2019-25671)
slug: 2026-04-va-max-rce
description: VA MAX 8.3.4 is vulnerable to remote code execution (CVE-2019-25671), allowing authenticated attackers to execute arbitrary commands by injecting shell metacharacters into the mtu_eth0 parameter via a POST request to changeip.php.
date: "2026-04-05T21:16:44Z"
severities:
  - critical
type: advisory
types:
  - advisory
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

VA MAX 8.3.4 is susceptible to a remote code execution (RCE) vulnerability identified as CVE-2019-25671. This vulnerability allows authenticated attackers to inject shell metacharacters into the `mtu_eth0` parameter, leading to arbitrary command execution. The attack vector involves sending crafted POST requests to the `changeip.php` endpoint. Successful exploitation grants the attacker the ability to execute commands as the `apache` user. This vulnerability poses a significant risk to organizations using the affected VA MAX version, as it can lead to complete system compromise. Given the ease of exploitation and the potential for significant impact, defenders need to prioritize detection and mitigation efforts.

## Attack Chain

1.  Attacker authenticates to the VA MAX 8.3.4 web interface using valid credentials.
2.  Attacker crafts a malicious POST request targeting the `changeip.php` endpoint.
3.  The POST request includes the `mtu_eth0` parameter containing shell metacharacters and the desired command for execution.
4.  The `changeip.php` script processes the `mtu_eth0` parameter without proper sanitization or validation.
5.  The injected shell metacharacters are interpreted by the system, leading to command execution.
6.  The attacker-supplied command is executed with the privileges of the `apache` user.
7.  The attacker gains control of the system, potentially installing malware, exfiltrating data, or performing other malicious activities.

## Impact

Successful exploitation of CVE-2019-25671 allows an attacker to execute arbitrary commands on the affected VA MAX 8.3.4 system. This can lead to complete system compromise, data theft, and disruption of services. If VA MAX manages critical infrastructure, this vulnerability could have significant real-world consequences. Given the publicly available exploit code, the risk of widespread exploitation is high.

## Recommendation

*   Monitor web server logs for POST requests to `changeip.php` containing shell metacharacters in the `mtu_eth0` parameter using the provided Sigma rule.
*   Apply appropriate input validation and sanitization to the `mtu_eth0` parameter within the `changeip.php` script.
*   Consider upgrading to a patched version of VA MAX that addresses CVE-2019-25671.
*   Implement network segmentation to limit the potential impact of a compromised VA MAX system.
*   Review and enforce strong password policies to prevent unauthorized access to the VA MAX web interface.
*   Monitor for suspicious processes spawned by the `apache` user, which could indicate successful exploitation of the RCE vulnerability using the Sigma rule `Detect Suspicious Processes Spawned by Apache`.
