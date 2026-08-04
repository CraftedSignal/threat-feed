---
title: Command Injection in Zyxel WAX650S export-cgi
slug: 2026-08-zyxel-export-cgi-rce
description: An authenticated administrator can exploit a command injection vulnerability in the export-cgi program of Zyxel WAX650S firmware versions through 7.10(ABRM.4)C0 to execute arbitrary OS commands.
date: "2026-08-04T03:43:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - command-injection
  - zyxel
  - network-infrastructure
vendors:
  - Zyxel
products:
  - WAX650S firmware
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A post-authentication command injection vulnerability in the export-cgi CGI program in Zyxel WAX650S firmware versions through 7.10(ABRM.4)C0 could allow an authenticated attacker with administrator privileges to execute OS commands on an affected device.
    confidence_band: high
cves:
  - id: CVE-2026-6837
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6837
  - https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-command-injection-and-improper-authentication-vulnerabilities-in-certain-aps-fwa7-and-security-routers-08-04-2026
rules:
  - title: Detect Potential CVE-2026-6837 Exploitation Attempt
    description: Detects HTTP requests to the export-cgi program potentially containing shell metacharacters indicating command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch firmware on Zyxel WAX650S
      owner: IT Operations
      due: 72h
      evidence: Vendor advisory confirms vulnerability in firmware <= 7.10(ABRM.4)C0.
---

CVE-2026-6837 describes a post-authentication command injection vulnerability affecting the 'export-cgi' CGI program within Zyxel WAX650S access point firmware. The vulnerability exists in all firmware versions up to and including 7.10(ABRM.4)C0. An attacker who has already obtained legitimate administrative credentials for the web management interface can leverage this flaw to inject and execute arbitrary commands at the operating system level. Because this vulnerability requires existing administrative access, the primary risk involves privilege escalation or persistence for an attacker who has successfully performed initial credential compromise. Organizations utilizing these devices should prioritize upgrading to patched firmware versions and auditing active administrative sessions.

## Attack Chain

1. Attacker performs credential theft or brute-force to obtain administrator-level access to the web management interface.
2. Attacker logs into the device management console via HTTP or HTTPS.
3. Attacker navigates to or directly crafts a request to the 'export-cgi' endpoint.
4. Attacker injects malicious OS command sequences into the request parameters processed by 'export-cgi'.
5. The CGI program fails to neutralize shell metacharacters, passing the input directly to the system shell.
6. The system executes the injected commands with the privileges of the web service process.
7. Attacker establishes persistent access or exfiltrates configuration data from the device.

## Impact

Successful exploitation allows for full control of the affected Zyxel WAX650S access point. This can lead to total loss of device confidentiality, integrity, and availability, as well as the potential for the device to be used as a pivot point for further lateral movement within the network.

## Recommendation

* Apply the vendor-provided firmware update that addresses CVE-2026-6837 on all Zyxel WAX650S units immediately.
* Audit web server access logs for anomalous POST or GET requests directed at 'export-cgi' by known administrative accounts.
* Limit access to the device management interface to specific internal management VLANs or dedicated jump hosts to minimize the exposure of administrative endpoints.
* Monitor for unexpected system processes or network connections originating from the WAX650S device.
