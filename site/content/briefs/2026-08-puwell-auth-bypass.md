---
title: Authentication Bypass in Puwell IP Camera Firmware
slug: 2026-08-puwell-auth-bypass
description: Puwell IP Camera firmware versions 2.x through 4.x contain an authentication bypass vulnerability (CVE-2026-61514) allowing unauthenticated attackers to control device functions via TCP port 23456.
date: "2026-08-04T15:43:50Z"
lastmod: "2026-08-04T15:43:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Puwell Technology Inc.
  - Puwell
products:
  - IP Camera
  - IP Camera (firmware 2.x - 4.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Puwell IP Camera firmware versions 2.x through 4.x contains an authentication bypass vulnerability that allows unauthenticated attackers to access device functions by sending protocol-conforming packets over TCP port 23456 without credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can exploit the unvalidated Session field in the proprietary control protocol header to access live video streams, control pan and tilt motors, activate audio functions, and remotely restart the device.
    confidence_band: high
cves:
  - id: CVE-2026-61514
    cvss: 9.8
  - id: CVE-2026-61515
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61514
  - https://www.vulncheck.com/advisories/puwell-ip-camera-2-x-4-x-unauthenticated-access-via-tcp-port-23456
  - https://damiri.fr/fr/cve/CVE-2026-61514
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61515
iocs:
  - type: port
    value: "34567"
ioc_counts:
  port: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block ingress traffic to TCP port 23456 on perimeter firewalls for internal IP camera assets
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthenticated access via TCP port 23456
  mitigation_plan:
    - priority: immediate
      action: Isolate IP cameras into a dedicated, non-routable management network
      owner: IT Operations
      addresses: CVE-2026-61514
      evidence: Unauthenticated access vulnerability
updates:
  - at: "2026-08-04T15:43:54Z"
    level: L2
    summary: added CVE-2026-61515; ip camera version firmware 2.x - 4.x
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-61515
---

Puwell IP Camera firmware versions 2.x through 4.x are affected by an authentication bypass vulnerability, identified as CVE-2026-61514. The flaw resides in the proprietary control protocol used by the devices, specifically in how they handle the Session field within the protocol header. An unauthenticated attacker can send crafted, protocol-conforming packets to TCP port 23456 to bypass security checks. Successful exploitation grants an attacker full control over the device, including the ability to view live video streams, manipulate pan and tilt motor functions, toggle audio recording, or force a remote device restart. This vulnerability poses a significant risk to the integrity and privacy of environments deploying these cameras, as it requires no credentials to execute.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable Puwell IP Cameras listening on TCP port 23456.
2. Attacker initiates a connection to the target device on TCP port 23456.
3. Attacker crafts a protocol-conforming packet for the proprietary control interface.
4. Attacker inserts arbitrary or malformed data into the Session field of the packet header.
5. The target device fails to validate the Session identifier, granting the attacker an authenticated context.
6. Attacker sends follow-up command packets to interact with device functions (e.g., streaming, motor control, or rebooting).
7. The device executes the commands without requiring legitimate administrative credentials.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain unauthorized access to live surveillance video, control physical camera hardware, activate audio, and cause denial-of-service through device reboots. This affects all Puwell IP Cameras running firmware versions 2.x through 4.x, potentially leading to unauthorized physical surveillance and manipulation of security infrastructure.

## Recommendation

Prioritized actions for security and infrastructure teams:
- Immediately segment Puwell IP Cameras from the internet and place them in a restricted management VLAN.
- Implement firewall rules to block unsolicited ingress traffic on TCP port 23456 to these devices.
- Audit network logs for unexpected traffic patterns targeting TCP port 23456.
- Check with the vendor (Puwell Technology Inc.) for firmware updates addressing CVE-2026-61514.
