---
title: Remote Command Injection Vulnerability in GL.iNet GL-MT3000
slug: 2026-08-glinet-rce
description: A critical command injection vulnerability in the nas-web RPC Wrapper of GL.iNet GL-MT3000 routers allows unauthenticated remote attackers to execute arbitrary system commands via the /cgi-bin/glc interface.
date: "2026-08-04T01:42:26Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - cve-2026-18686
  - command-injection
  - iot
  - rce
vendors:
  - GL.iNet
products:
  - GL-MT3000
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Performing a manipulation results in command injection.
    confidence_band: high
cves:
  - id: CVE-2026-18686
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18686
  - https://github.com/coconut652-7/IOT_Vul_Public/tree/main/Glinet/MT3000/nas-web/ADD_USER_ADD_SHARE
  - https://vuldb.com/cve/CVE-2026-18686
iocs:
  - type: url
    value: https://github.com/coconut652-7/IOT_Vul_Public/tree/main/Glinet/MT3000/nas-web/ADD_USER_ADD_SHARE
ioc_counts:
  url: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch GL.iNet GL-MT3000 firmware to version > 4.4.5
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18686 vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to administration interface
      owner: Network Security
      addresses: CVE-2026-18686
      evidence: Vulnerability allows unauthenticated remote access
---

A critical command injection vulnerability, identified as CVE-2026-18686, affects the GL.iNet GL-MT3000 router running firmware versions up to and including 4.4.5. The vulnerability resides within the 'nas-web.add_user' function of the 'nas-web' RPC wrapper, which is accessible via the '/cgi-bin/glc' endpoint. 

The flaw allows an unauthenticated, remote attacker to trigger command injection by manipulating inputs sent to this specific RPC handler. Because this interface is reachable over the network, it presents a significant risk to affected devices. Proof-of-concept (PoC) exploit code is publicly available, increasing the likelihood of exploitation. This vulnerability is categorized under CWE-77 (Improper Neutralization of Special Elements used in a Command). Given the high base CVSS score, owners of these devices are advised to update firmware immediately upon the availability of security patches.

## Attack Chain

1. Attacker performs network reconnaissance to identify GL.iNet GL-MT3000 devices exposing the web administration interface.
2. Attacker crafts a malicious HTTP request directed at the '/cgi-bin/glc' endpoint.
3. The request targets the 'nas-web.add_user' function within the nas-web RPC wrapper.
4. The attacker injects shell metacharacters into the input parameters expected by the function.
5. The application fails to sanitize the input, passing the attacker-supplied string directly to a system-level command execution routine.
6. The router executes the injected commands with the privileges of the web service process.
7. Final objective: The attacker gains remote code execution on the device, potentially leading to full system compromise or persistence.

## Impact

Successful exploitation results in arbitrary command execution on the router with high-level privileges. This enables attackers to reconfigure the network device, exfiltrate sensitive configuration data, pivot into internal networks protected by the router, or deploy persistent malware. The vulnerability affects all users of GL-MT3000 running firmware version 4.4.5 or earlier, significantly increasing the attack surface for remote compromise.

## Recommendation

- Upgrade GL-MT3000 firmware to the latest available version provided by GL.iNet to patch CVE-2026-18686.
- Restrict access to the device web administration interface (/cgi-bin/glc) to trusted management IP addresses via internal firewall rules.
- Enable ingress monitoring on the network perimeter to identify HTTP POST requests directed at '/cgi-bin/glc' containing unexpected characters or command sequences (e.g., semicolons, pipe symbols, backticks).
- Review network logs for unusual outbound connections originating from GL-MT3000 routers, which may indicate post-exploitation activity.
