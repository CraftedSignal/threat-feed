---
title: Remote Command Injection in GL.iNet GL-MT3000
slug: 2026-08-gl-inet-rce
description: Multiple unauthenticated remote command injection vulnerabilities in the GL.iNet GL-MT3000 router allow arbitrary code execution via the /cgi-bin/glc component. Public exploit code is available; patch firmware immediately.
date: "2026-08-04T01:42:16Z"
lastmod: "2026-08-04T13:48:34Z"
type: advisory
types:
  - advisory
  - threat
severities:
  - critical
exploited: true
tags:
  - cve
  - rce
  - iot
  - router
  - cve-2026-18686
  - command-injection
vendors:
  - GL.iNet
products:
  - GL-MT3000
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Such manipulation leads to command injection.
    confidence_band: high
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
  - id: CVE-2026-18685
    cvss: 9.8
  - id: CVE-2026-18686
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18685
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18686
  - https://github.com/StrTzz123/iot_vul/tree/main/GL-iNet/MT3000/4.4.5/modem_set_upgrade_glc_rce
  - https://github.com/coconut652-7/IOT_Vul_Public/tree/main/Glinet/MT3000/nas-web/ADD_USER_ADD_SHARE
  - https://vuldb.com/cve/CVE-2026-18686
iocs:
  - type: url
    value: https://github.com/StrTzz123/iot_vul/tree/main/GL-iNet/MT3000/4.4.5/modem_set_upgrade_glc_rce
  - type: url
    value: https://github.com/coconut652-7/IOT_Vul_Public/tree/main/Glinet/MT3000/nas-web/ADD_USER_ADD_SHARE
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-18685 Exploitation - Potential Command Injection in /cgi-bin/glc
    description: Detects HTTP requests to the vulnerable /cgi-bin/glc endpoint which may contain injected shell commands.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch all GL.iNet GL-MT3000 devices to firmware version > 4.4.5
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18685 and CVE-2026-18686 advisories
  hunt_leads:
    - lead: Identify all devices in inventory matching affected firmware range
      technique_id: T1190
      data_needed:
        - Asset management data
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Affected product list from NVD
  mitigation_plan:
    - priority: immediate
      action: Block or restrict access to the web management interface of GL-MT3000 devices
      owner: IT Operations
      addresses: CVE-2026-18685
      evidence: NVD vulnerability details
    - priority: immediate
      action: Restrict external access to administration interface
      owner: Network Security
      addresses: CVE-2026-18686
      evidence: Vulnerability allows unauthenticated remote access
  gaps:
    - Visibility into legacy management console logs
updates:
  - at: "2026-08-04T13:48:34Z"
    level: L2
    summary: 'Merged related GL.iNet GL-MT3000 command injection vulnerabilities (CVE-2026-18685, CVE-2026-18686) into a single advisory'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18685
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18686
aliases:
  - 2026-08-glinet-rce
---

Multiple critical command injection vulnerabilities have been identified in the GL.iNet GL-MT3000 router running firmware versions up to and including 4.4.5. Publicly available exploit code has been disclosed, significantly lowering the barrier for exploitation. Organizations deploying this hardware should prioritize applying firmware updates and restricting access to the management interface.

## CVE-2026-18685 — set_upgrade in modem.so

A critical security vulnerability (CVE-2026-18685) has been identified in the GL.iNet GL-MT3000 router, specifically within the `set_upgrade` function located in the `modem.so` component, invoked via `/cgi-bin/glc`. This flaw enables unauthenticated, remote attackers to perform command injection, leading to full system compromise.

### Attack Chain

1. An attacker identifies an internet-facing GL.iNet GL-MT3000 router.
2. The attacker sends a crafted HTTP request to the target device.
3. The request targets the `/cgi-bin/glc` binary.
4. The input is passed to the vulnerable `set_upgrade` function within `modem.so` without proper sanitization.
5. The `set_upgrade` function processes the malicious input, leading to command injection.
6. The injected commands are executed by the underlying operating system.
7. The attacker achieves arbitrary code execution with elevated privileges on the router.

### Impact

Successful exploitation results in full remote control of the affected router. Attackers can leverage the compromised device to intercept network traffic, gain a foothold in the local network, or use the device as part of a botnet. Given the nature of these routers, this compromise presents a significant risk to the privacy and security of all connected clients.

## CVE-2026-18686 — nas-web.add_user in nas-web RPC Wrapper

A critical command injection vulnerability, identified as CVE-2026-18686, affects the GL.iNet GL-MT3000 router. The vulnerability resides within the `nas-web.add_user` function of the `nas-web` RPC wrapper, which is accessible via the `/cgi-bin/glc` endpoint. The flaw allows an unauthenticated, remote attacker to trigger command injection by manipulating inputs sent to this specific RPC handler.

### Attack Chain

1. Attacker performs network reconnaissance to identify GL.iNet GL-MT3000 devices exposing the web administration interface.
2. Attacker crafts a malicious HTTP request directed at the `/cgi-bin/glc` endpoint.
3. The request targets the `nas-web.add_user` function within the nas-web RPC wrapper.
4. The attacker injects shell metacharacters into the input parameters expected by the function.
5. The application fails to sanitize the input, passing the attacker-supplied string directly to a system-level command execution routine.
6. The router executes the injected commands with the privileges of the web service process.
7. Final objective: The attacker gains remote code execution on the device, potentially leading to full system compromise or persistence.

### Impact

Successful exploitation results in arbitrary command execution on the router with high-level privileges. This enables attackers to reconfigure the network device, exfiltrate sensitive configuration data, pivot into internal networks protected by the router, or deploy persistent malware. The vulnerability affects all users of GL-MT3000 running firmware version 4.4.5 or earlier, significantly increasing the attack surface for remote compromise.

## Recommendation

- Identify all GL.iNet GL-MT3000 devices in the environment and verify the currently installed firmware version.
- Patch affected devices to the latest firmware version released by GL.iNet immediately to mitigate CVE-2026-18685 and CVE-2026-18686.
- Restrict access to the router's web management interface to trusted internal management subnets.
- Restrict access to the device web administration interface (`/cgi-bin/glc`) to trusted management IP addresses via internal firewall rules.
- Monitor edge device traffic for unusual HTTP requests targeting `/cgi-bin/glc` originating from external sources.
- Enable ingress monitoring on the network perimeter to identify HTTP POST requests directed at `/cgi-bin/glc` containing unexpected characters or command sequences (e.g., semicolons, pipe symbols, backticks).
- Review network logs for unusual outbound connections originating from GL-MT3000 routers, which may indicate post-exploitation activity.
