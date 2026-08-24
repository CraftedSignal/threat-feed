---
title: Remote Command Injection in DrayTek VigorAP dray_apm Component
slug: 2026-08-draytek-rce
description: Multiple DrayTek VigorAP models are vulnerable to pre-authentication remote command injection due to insufficient UDP input validation in the dray_apm component.
date: "2026-08-24T20:02:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - DrayTek
products:
  - VigorAP 918R
  - VigorAP 960C
  - VigorAP 1060C
  - VigorAP 906
  - VigorAP 912C
  - VigorAP 903
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote attacker can trigger this vulnerability via a crafted message to execute arbitrary commands with root privileges.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerability is caused by insufficient validation of UDP message content after START_SPEED_TEST before command execution.
    confidence_band: high
cves:
  - id: CVE-2026-71914
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71914
  - https://www.draytek.com/about/security-advisory/multiple-remote-code-execution-and-buffer-overflow-vulnerabilities-in-vigorap-series-august-2026/
  - https://www.vulncheck.com/advisories/draytek-vigorap-multiple-models-pre-authentication-os-command-injection-via-dray-apm
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Deploy vendor firmware updates to all vulnerable VigorAP devices.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-71914 requires firmware patches to resolve command injection vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict management/speed test ports via network ACLs.
      owner: IT Operations
      addresses: CVE-2026-71914
      evidence: Source advisory recommends updating firmware; network restriction prevents unauthenticated remote access.
---

DrayTek has disclosed a critical remote code execution vulnerability (CVE-2026-71914) affecting multiple VigorAP access point models. The vulnerability resides within the dray_apm component, which is responsible for device management and speed testing functionality. An unauthenticated remote attacker can exploit this flaw by sending a crafted UDP packet to the device. Specifically, the dray_apm component fails to properly validate the content of UDP messages sent after a START_SPEED_TEST command is issued. This lack of validation allows an attacker to inject and execute arbitrary commands with root-level privileges on the underlying operating system. Given the nature of these devices as network infrastructure, successful exploitation allows full control over the access point, potentially enabling further lateral movement within the network or man-in-the-middle attacks on connected wireless clients.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable DrayTek VigorAP management interfaces or specific UDP ports associated with the dray_apm component.
2. Attacker crafts a malicious UDP packet containing a payload designed to trigger the dray_apm speed test sequence.
3. Attacker appends command injection characters or malicious shell syntax to the payload following the START_SPEED_TEST identifier.
4. Attacker transmits the crafted UDP packet to the target VigorAP device.
5. The dray_apm component on the target device receives and processes the UDP message.
6. Insufficient input validation leads the device to parse the malicious content as part of an OS command.
7. The device executes the injected payload with root privileges.
8. Attacker gains persistent access or initiates further exfiltration/lateral movement from the compromised access point.

## Impact

Successful exploitation results in full root-level compromise of the affected DrayTek VigorAP access points. This grants an attacker complete control over network traffic flowing through the device, potentially facilitating data interception, redirection, or unauthorized access to the internal network. Affected models include the VigorAP 918R, 960C, 1060C, 906, 912C, and 903. Customers should prioritize firmware updates immediately to mitigate this critical risk.

## Recommendation

* Apply the official vendor firmware updates provided by DrayTek to all affected VigorAP models to remediate CVE-2026-71914.
* Restrict access to the management and speed test ports of VigorAP devices to trusted administrative IP addresses using firewall rules or ACLs to prevent unauthenticated remote access.
* Monitor network traffic for unusual UDP patterns directed at DrayTek devices, specifically identifying high-frequency or anomalous UDP packets involving the dray_apm service.
* Conduct a security audit of network edge infrastructure to identify vulnerable VigorAP firmware versions identified in the affected products list.
