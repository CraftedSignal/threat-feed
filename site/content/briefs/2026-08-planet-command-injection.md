---
title: Authenticated OS Command Injection in PLANET GS-4210-16P2S
slug: 2026-08-planet-command-injection
description: PLANET GS-4210-16P2S switches running firmware older than 3.441b260626 are vulnerable to authenticated OS command injection via the memberTags parameter.
date: "2026-08-28T21:37:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:planet:gs_4210_16p2s:*:*:*:*:*:*:*:*
tags:
  - cve-2026-75121
  - command-injection
  - network-security
vendors:
  - PLANET
products:
  - GS-4210-16P2S (< 3.441b260626)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote authenticated attacker can send a crafted memberTags value to execute arbitrary operating-system commands on the device.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The web_vlan_membership_edit_dialog_post handler incorporates the memberTags POST parameter into a shell command without sanitization.
    confidence_band: high
cves:
  - id: CVE-2026-75121
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75121
rules:
  - title: Detects CVE-2026-75121 Exploitation - Authenticated Command Injection in /cgi-bin/dispatcher.cgi
    description: Detects attempts to exploit CVE-2026-75121 by monitoring for shell metacharacters in the memberTags POST parameter sent to the dispatcher.cgi endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor for CVE-2026-75121 attempts
      owner: Detection Engineering
      due: 24h
      evidence: High CVSS score suggests immediate protection
  mitigation_plan:
    - priority: immediate
      action: Upgrade GS-4210-16P2S firmware to 3.441b260626 or later
      owner: IT Operations
      addresses: CVE-2026-75121
      evidence: Fixed version specified by NVD
---

PLANET GS-4210-16P2S network switches running firmware versions prior to 3.441b260626 are susceptible to an authenticated OS command injection vulnerability. The flaw exists within the /cgi-bin/dispatcher.cgi endpoint, specifically handled by the web_vlan_membership_edit_dialog_post function. An attacker with valid administrative or authenticated credentials can craft a malicious HTTP POST request containing a manipulated memberTags parameter. Because the application fails to properly sanitize this input before passing it to the underlying system shell, an attacker can execute arbitrary operating-system commands with the privileges of the web management process. This vulnerability is tracked as CVE-2026-75121 and poses a significant risk for lateral movement or persistence on the internal network through compromised networking infrastructure.

## Impact

Successful exploitation allows an authenticated attacker to gain full command execution on the target GS-4210-16P2S switch. This can lead to unauthorized configuration changes, traffic interception, network reconnaissance, or the use of the switch as a staging point for further attacks within the local area network. Given the role of these devices in managing VLANs and internal traffic, compromise could have broad ramifications for internal segmentation and security policy enforcement.

## Recommendation

Prioritized actions for security operations and IT teams include:
- Patching: Update all PLANET GS-4210-16P2S devices to firmware version 3.441b260626 or later immediately.
- Access Control: Limit access to the device web management interface to trusted administrative IPs only using hardware-based ACLs or isolated management VLANs.
- Credential Management: Audit and rotate all administrative credentials on PLANET switches to reduce the risk of unauthorized access required for this exploitation.
- Monitoring: Monitor web server access logs for anomalous POST requests to /cgi-bin/dispatcher.cgi, particularly those containing shell metacharacters in the memberTags field.
