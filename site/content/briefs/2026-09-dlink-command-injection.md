---
title: Remote OS Command Injection in D-Link DNS-320 ShareCenter
slug: 2026-09-dlink-command-injection
description: D-Link DNS-320 ShareCenter version 2.06B01 contains a remote OS command injection vulnerability in the File Sharing component, allowing unauthenticated attackers to execute arbitrary system commands.
date: "2026-09-03T23:23:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:dlink:dns-320:2.06b01:*:*:*:*:*:*:*
tags:
  - cve-2026-85224
  - nas
  - command-injection
  - remote-code-execution
vendors:
  - D-Link
products:
  - DNS-320 ShareCenter (2.06B01)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely via the /cgi/file_sharing.cgi component.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Executing a manipulation of the argument fileurl can lead to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-85224
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85224
rules:
  - title: Detects CVE-2026-85224 Exploitation - Remote OS Command Injection
    description: Detects attempts to exploit CVE-2026-85224 by identifying shell metacharacters within the fileurl argument of the /cgi/file_sharing.cgi endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit network perimeter for D-Link DNS-320 devices reachable from the internet.
      owner: SOC
      due: 24h
      evidence: The exploit can be launched remotely.
  mitigation_plan:
    - priority: immediate
      action: Remove public-facing access to the web management interface for affected D-Link devices.
      owner: IT Operations
      addresses: CVE-2026-85224
      evidence: The vulnerability allows unauthenticated remote OS command injection.
---

D-Link DNS-320 ShareCenter version 2.06B01 is susceptible to an unauthenticated remote OS command injection vulnerability. The flaw exists within the File Sharing component, specifically affecting the /cgi/file_sharing.cgi script. An attacker can trigger this vulnerability by sending a maliciously crafted request to the device, manipulating the 'fileurl' argument. Because this vulnerability allows for arbitrary command execution on the underlying operating system, it poses a significant risk to the integrity and confidentiality of the affected device. Publicly disclosed exploit code currently exists for this CVE, increasing the likelihood of exploitation. Defensive teams should prioritize remediation, as this vulnerability provides a direct pathway for unauthenticated actors to gain control of vulnerable network-attached storage (NAS) devices.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to execute arbitrary commands with the privileges of the web server on the D-Link DNS-320 ShareCenter device. This can lead to complete system compromise, unauthorized data access, persistence establishment, or the device's inclusion in botnet activity. Given the nature of NAS devices, potential impacts include the exfiltration or encryption of stored files and the use of the device as a pivot point within the local network.

## Recommendation

1. Identify all internet-facing D-Link DNS-320 ShareCenter devices within your environment using network scanning or asset inventory tools.
2. Restrict management interface access to trusted administrative networks only; ensure these devices are not exposed to the public internet.
3. Monitor web server access logs for anomalous HTTP requests targeting /cgi/file_sharing.cgi containing shell metacharacters in the fileurl parameter.
4. Evaluate the necessity of continuing the use of this legacy hardware, as specific security patches for version 2.06B01 may be unavailable; segment affected devices from sensitive internal networks.
