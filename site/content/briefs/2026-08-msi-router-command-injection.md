---
title: Command Injection in MSI Radix AXE6600 Router
slug: 2026-08-msi-router-command-injection
description: The MSI Radix AXE6600 router firmware version v781521 is vulnerable to remote command injection via the wps.cgi interface, allowing unauthenticated attackers to execute arbitrary commands with root privileges.
date: "2026-08-08T23:42:11Z"
lastmod: "2026-08-09T01:44:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - MSI
products:
  - Radix AXE6600 (v781521)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MSI Radix AXE6600 router firmware version v781521 contains a command injection vulnerability in the wps.cgi interface that allows remote attackers to execute arbitrary commands
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Attackers can exploit these unsanitized parameters to execute arbitrary commands on the affected device
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can exploit these unsanitized parameters to execute arbitrary commands on the affected device and obtain root privileges.
    confidence_band: high
cves:
  - id: CVE-2026-71983
    cvss: 9.8
  - id: CVE-2026-71984
    cvss: 9.8
  - id: CVE-2026-71985
    cvss: 9.8
  - id: CVE-2026-71986
    cvss: 9.8
  - id: CVE-2026-71987
    cvss: 9.8
  - id: CVE-2026-71989
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71983
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71984
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71985
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71986
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71987
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71988
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71989
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71990
rules:
  - title: Detects CVE-2026-71983 Exploitation - Command Injection in wps.cgi
    description: Detects attempted command injection targeting the wps.cgi endpoint on MSI Radix AXE6600 routers using shell metacharacters in specific parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch MSI Radix AXE6600 firmware to remediate CVE-2026-71983
      owner: IT Operations
      due: 48h
      evidence: Critical vulnerability (CVSS 9.8) requires immediate firmware remediation.
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface access
      owner: IT Operations
      addresses: CVE-2026-71983
      evidence: Prevent remote exploitation by limiting exposure to administrative interfaces.
updates:
  - at: "2026-08-09T01:42:41Z"
    level: L2
    summary: added CVE-2026-71984, CVE-2026-71985
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71984
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71985
  - at: "2026-08-09T01:43:15Z"
    level: L2
    summary: added CVE-2026-71986, CVE-2026-71987
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71986
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71987
  - at: "2026-08-09T01:44:22Z"
    level: L2
    summary: added CVE-2026-71989
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71990
---

The MSI Radix AXE6600 router running firmware version v781521 contains a critical command injection vulnerability in its web-based management interface. The vulnerability exists within the wps.cgi file, which fails to properly sanitize user-supplied input provided via the pin2g, pin5g, or pin6g parameters. An unauthenticated remote attacker can supply malicious payloads to these parameters to execute arbitrary commands on the underlying operating system. Because the web service operates with high privileges, successful exploitation results in full root access to the device. This poses a significant risk to the integrity and confidentiality of the network, as the compromised router can be used to facilitate man-in-the-middle attacks, exfiltration, or further lateral movement into the internal network. Defenders should monitor for anomalous HTTP requests targeting this specific CGI endpoint.

## Impact

Successful exploitation of CVE-2026-71983 allows an attacker to achieve unauthenticated remote code execution with root-level privileges on the target router. This provides full control over the gateway device, enabling the attacker to intercept or modify all traffic traversing the device, pivot into the local area network, or persist across reboots.

## Recommendation

* Immediately update the firmware of all MSI Radix AXE6600 routers to the latest available version provided by the manufacturer to remediate CVE-2026-71983.
* Restrict access to the router web management interface (port 80/443) so that it is only accessible from trusted administrative IP addresses rather than the internet.
* Monitor perimeter firewall and proxy logs for HTTP GET or POST requests directed at /wps.cgi that contain suspicious characters (such as semicolons, pipes, or backticks) within the pin2g, pin5g, or pin6g parameters.
