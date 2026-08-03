---
title: Remote Command Injection in GL.iNet GL-MT3000 Firmware
slug: 2026-08-gl-inet-rce
description: A command injection vulnerability in the Logread Lua RPC plugin of GL.iNet GL-MT3000 firmware versions 4.4.5 and earlier allows authenticated remote attackers to execute arbitrary system commands via the module argument.
date: "2026-08-03T14:03:31Z"
lastmod: "2026-08-03T23:42:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - command-injection
  - cve-2026-18598
  - iot-security
  - cve-2026-18599
  - router
  - rce
  - cve-2026-18601
  - iot
vendors:
  - GL.iNet
products:
  - GL-MT3000
  - GL-MT3000 (<= 4.4.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument module results in command injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This manipulation of the argument record_size causes command injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Performing a manipulation of the argument filename results in command injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Such manipulation of the argument switch leads to command injection.
    confidence_band: high
cves:
  - id: CVE-2026-18598
    cvss: 8.8
  - id: CVE-2026-18602
    cvss: 9.8
  - id: CVE-2026-18599
    cvss: 8
  - id: CVE-2026-18601
    cvss: 9.8
  - id: CVE-2026-18600
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18598
  - https://github.com/StrTzz123/iot_vul/blob/main/GL-iNet/MT3000/4.4.5/logread_get_system_log_rpc_rce/CVE.md
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18599
  - https://github.com/StrTzz123/iot_vul/blob/main/GL-iNet/MT3000/4.4.5/logread_set_config_rpc_rce/CVE.md
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18601
  - https://github.com/StrTzz123/iot_vul/blob/main/GL-iNet/MT3000/4.4.5/ovpn_check_config_glc_rce/CVE.md
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18600
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18602
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18684
  - https://github.com/StrTzz123/iot_vul/tree/main/GL-iNet/MT3000/4.4.5/modem_remove_profile_glc_rce
rules:
  - title: Detects CVE-2026-18598 Exploitation - Remote Command Injection
    description: Detects exploitation attempts against the Logread Lua RPC plugin by searching for shell metacharacters within the module parameter of HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
  - title: Detect CVE-2026-18601 Exploitation - RCE via /cgi-bin/glc
    description: Detects exploitation attempts against CVE-2026-18601 by identifying HTTP requests to the /cgi-bin/glc endpoint containing shell injection metacharacters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-18684 Exploitation - Command Injection in GL.iNet
    description: Detects exploitation attempts against the /cgi-bin/glc endpoint where shell injection characters are used in the URI query string.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 3
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch firmware on all GL-MT3000 devices to version > 4.4.5
      owner: IT Operations
      due: 24h
      evidence: Vulnerability exists in firmware up to 4.4.5.
  mitigation_plan:
    - priority: immediate
      action: Disable external access to management interface
      owner: IT Operations
      addresses: CVE-2026-18598
      evidence: Attack can be launched remotely.
updates:
  - at: "2026-08-03T14:03:43Z"
    level: L2
    summary: 'merged source coverage: Command Injection in GL.iNet GL-MT3000 Firmware'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18599
  - at: "2026-08-03T16:04:15Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-18601 Exploitation - RCE via /cgi-bin/glc'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18601
  - at: "2026-08-03T16:04:58Z"
    level: L2
    summary: 'merged source coverage: Remote Command Injection in GL.iNet GL-MT3000 Network Lua RPC Plugin'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18600
  - at: "2026-08-03T18:05:31Z"
    level: L2
    summary: added CVE-2026-18599 +3; gl-mt3000 version <= 4.4.5
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18602
  - at: "2026-08-03T23:42:18Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-18684 Exploitation - Command Injection in GL.iNet'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18684
---

A critical security vulnerability (CVE-2026-18598) exists in the GL.iNet GL-MT3000 wireless router, affecting firmware versions up to 4.4.5. The vulnerability is located within the Logread Lua RPC plugin, specifically in the `logread.get_system_log` function handled by the `/usr/lib/oui-httpd/rpc/logread` file. An authenticated remote attacker can manipulate the `module` argument to inject and execute arbitrary system commands on the underlying host operating system. This vulnerability stems from improper neutralization of special elements used in command execution (CWE-77). Public exploit code for this flaw is available, significantly lowering the barrier for exploitation. Given the network-facing nature of these devices, organizations should prioritize updating to a patched firmware version or restricting access to the management RPC interface.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable GL.iNet management interfaces.
2. Attacker obtains valid low-privileged credentials for the GL-MT3000 web management portal.
3. Attacker accesses the OUI-based RPC service endpoint used by the Logread Lua RPC plugin.
4. Attacker crafts a malicious HTTP request containing a payload injected into the `module` argument of the `logread.get_system_log` function.
5. The `oui-httpd` service processes the request and passes the tainted `module` argument to the system shell.
6. The system shell executes the attacker-supplied commands with the privileges of the web service process.
7. Attacker achieves remote code execution for persistence, further system exploitation, or network traversal.

## Impact

Successful exploitation allows unauthenticated (if PR is bypassed) or low-privileged remote attackers to gain full control over the router. This can lead to complete compromise of the network traffic passing through the device, unauthorized exfiltration of sensitive information, or the potential for lateral movement into the internal network protected by the router.

## Recommendation

* Update GL-MT3000 firmware to version 4.4.6 or later immediately to patch CVE-2026-18598.
* Disable remote access to the web management interface on all internet-facing GL.iNet devices.
* Implement strictly limited access control lists (ACLs) for the device management interface.
* Monitor network logs for unusual HTTP POST requests to `/rpc/logread` or similar paths containing shell metacharacters such as semicolon, pipe, or backticks in query parameters.
