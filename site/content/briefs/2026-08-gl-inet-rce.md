---
title: Remote Command Injection in GL.iNet GL-MT3000
slug: 2026-08-gl-inet-rce
description: An unauthenticated remote command injection vulnerability in the GL.iNet GL-MT3000 router allows arbitrary code execution via the /cgi-bin/glc component.
date: "2026-08-04T01:42:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - rce
  - iot
  - router
vendors:
  - GL.iNet
products:
  - GL-MT3000 (Firmware <= 4.4.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Such manipulation leads to command injection.
    confidence_band: high
cves:
  - id: CVE-2026-18685
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18685
  - https://github.com/StrTzz123/iot_vul/tree/main/GL-iNet/MT3000/4.4.5/modem_set_upgrade_glc_rce
iocs:
  - type: url
    value: https://github.com/StrTzz123/iot_vul/tree/main/GL-iNet/MT3000/4.4.5/modem_set_upgrade_glc_rce
ioc_counts:
  url: 1
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
      evidence: CVE-2026-18685 Advisory
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
  gaps:
    - Visibility into legacy management console logs
---

A critical security vulnerability (CVE-2026-18685) has been identified in the GL.iNet GL-MT3000 router, specifically within the `set_upgrade` function located in the `modem.so` component, invoked via `/cgi-bin/glc`. This flaw enables unauthenticated, remote attackers to perform command injection, leading to full system compromise. The vulnerability affects firmware versions up to 4.4.5. Publicly available exploit code has been disclosed, significantly lowering the barrier for exploitation by malicious actors. Given the remote accessibility of the target interface and the availability of proof-of-concept material, organizations deploying this hardware should prioritize applying firmware updates or restricting access to the management interface.

## Attack Chain

1. An attacker identifies an internet-facing GL.iNet GL-MT3000 router.
2. The attacker sends a crafted HTTP request to the target device.
3. The request targets the `/cgi-bin/glc` binary.
4. The input is passed to the vulnerable `set_upgrade` function within `modem.so` without proper sanitization.
5. The `set_upgrade` function processes the malicious input, leading to command injection.
6. The injected commands are executed by the underlying operating system.
7. The attacker achieves arbitrary code execution with elevated privileges on the router.

## Impact

Successful exploitation results in full remote control of the affected router. Attackers can leverage the compromised device to intercept network traffic, gain a foothold in the local network, or use the device as part of a botnet. Given the nature of these routers, this compromise presents a significant risk to the privacy and security of all connected clients.

## Recommendation

- Identify all GL.iNet GL-MT3000 devices in the environment and verify the currently installed firmware version.
- Patch affected devices to the latest firmware version released by GL.iNet immediately to mitigate CVE-2026-18685.
- Restrict access to the router's web management interface to trusted internal management subnets.
- Monitor edge device traffic for unusual HTTP requests targeting `/cgi-bin/glc` originating from external sources.
