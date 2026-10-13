---
title: Remote Command Injection in Wavlink WL-WN530BE1-A
slug: 2026-10-wavlink-rce
description: An unauthenticated remote command injection vulnerability in the Wavlink WL-WN530BE1-A router allows attackers to execute arbitrary system commands via the /cgi-bin/uploadVpn.cgi file.
date: "2026-10-13T08:33:23Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:wavlink:wl-wn530be1-a_firmware:251117:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - command-injection
  - iot
  - networking
vendors:
  - Wavlink
products:
  - WL-WN530BE1-A (251117)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Such manipulation of the argument Type leads to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-109108
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109108
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external management access to Wavlink WL-WN530BE1-A routers
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109108 allows unauthenticated remote command injection
  mitigation_plan:
    - priority: immediate
      action: Isolate vulnerable routers from internet-facing networks
      owner: IT Operations
      addresses: CVE-2026-109108
      evidence: Publicly available exploit for remote command injection
---

A critical remote command injection vulnerability, tracked as CVE-2026-109108, affects the Wavlink WL-WN530BE1-A router (firmware version 251117). The vulnerability resides in the /cgi-bin/uploadVpn.cgi script, where the 'Type' argument is improperly handled by the popen function. This flaw allows an unauthenticated, remote attacker to inject and execute arbitrary OS commands on the device. Because the exploit for this vulnerability has been disclosed publicly, there is a high risk of active exploitation against internet-facing routers. Organizations utilizing these devices must treat them as high-risk assets given the potential for full system compromise and unauthorized network access.

## Impact

Successful exploitation of CVE-2026-109108 grants an attacker remote command execution (RCE) with the privileges of the web service process. Given the role of the WL-WN530BE1-A as a network infrastructure device, this can lead to total system compromise, allowing attackers to intercept traffic, pivot into the local network, or use the device as a persistent staging point for further malicious activity.

## Recommendation

* Monitor network traffic for HTTP POST or GET requests to /cgi-bin/uploadVpn.cgi containing suspicious command characters in the 'Type' parameter (e.g., ;, |, &, backticks).
* Immediately restrict administrative access to the management interface of the WL-WN530BE1-A to trusted internal subnets or local loopback.
* Disconnect affected devices from the internet until a firmware patch is applied by the vendor.
