---
title: Unauthenticated Remote Code Execution in D-Link NAS Devices
slug: 2026-08-dlink-nas-rce
description: Multiple D-Link NAS devices are vulnerable to unauthenticated OS command injection via the account_mgr.cgi script, allowing remote attackers to execute arbitrary commands with root privileges.
date: "2026-08-17T14:54:35Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:dlink:dns-320_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dlink:dns-320lw_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dlink:dns-325_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dlink:dns-340l_firmware:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - nas
  - hardware
  - vulnerability
vendors:
  - D-Link
products:
  - DNS-320
  - DNS-320LW
  - DNS-325
  - DNS-340L
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The /cgi-bin/account_mgr.cgi script on several D-Link NAS devices is vulnerable to unauthenticated command injection.
    confidence_band: high
cves:
  - id: CVE-2024-10914
    cvss: 8.1
    epss: 0.97391
references:
  - https://www.exploit-db.com/exploits/52643
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10914
rules:
  - title: Detect CVE-2024-10914 Exploitation - OS Command Injection in account_mgr.cgi
    description: Detects exploitation attempts against D-Link NAS devices where the name parameter contains shell metacharacters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Security researchers have identified a critical unauthenticated OS command injection vulnerability (CVE-2024-10914) affecting multiple D-Link NAS device models, including the DNS-320, DNS-320LW, DNS-325, and DNS-340L. The vulnerability exists within the /cgi-bin/account_mgr.cgi script, where the 'name' parameter is directly concatenated into a system() call without adequate input sanitization. An attacker can inject shell metacharacters (specifically a semicolon) to terminate the intended command and execute arbitrary operating system commands with root privileges. 

D-Link has officially designated these products as End-of-Life (EoL) and has explicitly stated that no security patches will be issued. Given the existence of a public, functional exploit and reports of active exploitation in the wild, organizations currently utilizing these legacy storage devices face a significant risk of full system compromise. Defenders should prioritize the immediate isolation of these devices from internet-facing environments.

## Impact

Successful exploitation results in full remote code execution on the affected NAS hardware with root-level privileges. This enables attackers to exfiltrate sensitive data, install persistent backdoors, or utilize the devices as pivots within the internal network. Because the devices are end-of-life and lack vendor support, the impact is permanent for any device remaining connected to the network.

## Recommendation

* Immediately disconnect all affected D-Link NAS devices from the internet or place them behind a restrictive firewall that blocks access to /cgi-bin/account_mgr.cgi from untrusted networks.
* Implement web application firewall (WAF) rules to inspect incoming HTTP requests to /cgi-bin/account_mgr.cgi, specifically looking for shell metacharacters (e.g., ;, |, &, $) within the 'name' parameter.
* Deploy the provided Sigma rule to web server access logs to detect potential exploitation attempts.
* Identify and retire legacy NAS devices from the environment as they will not receive security updates for this or future vulnerabilities.
