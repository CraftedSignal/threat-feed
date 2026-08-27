---
title: Unauthenticated RCE in Unitree G1 EDU Firmware
slug: 2026-08-unitree-g1-rce
description: Unitree G1 EDU firmware through 1.5.2 is susceptible to unauthenticated remote code execution allowing root-level command injection via a chained exploit targeting the WebRTC-to-DDS bridge, hardcoded credentials, and path traversal in the knowledge upload API.
date: "2026-08-27T21:10:15Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Unitree
products:
  - G1 EDU
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unitree G1 EDU firmware through 1.5.2 contains an unauthenticated remote code execution vulnerability that allows network-adjacent attackers to execute arbitrary commands as root
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: trigger execution of that payload as uid 0 through the bashrunner shell subprocess
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials in Files'
    evidence: a static AES-128 key stored with world-readable permissions
    confidence_band: high
cves:
  - id: CVE-2026-76639
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76639
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch G1 EDU firmware to version 1.5.2 or higher
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-76639 vulnerability advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to TCP port 9991
      owner: Network Security
      addresses: CVE-2026-76639
      evidence: Exploitation relies on network-adjacent access to WebRTC-to-DDS bridge
---

Unitree G1 EDU firmware versions up to 1.5.2 are affected by a severe unauthenticated remote code execution vulnerability (CVE-2026-76639). The vulnerability stems from an insecure WebRTC-to-DDS bridge listening on TCP port 9991. By leveraging this bridge alongside a static AES-128 key discovered in world-readable storage and a path traversal flaw in the chat_go knowledge upload API, network-adjacent attackers can execute arbitrary code with root (uid 0) privileges. The vulnerability permits an attacker to manipulate the bashrunner service, allowing them to plant malicious payloads in execution directories and subsequently trigger their execution. This chain provides complete control over the robot platform, necessitating immediate firmware updates or the restriction of network access to the management interfaces.

## Attack Chain

1. An attacker identifies the target G1 EDU device reachable on TCP port 9991.
2. The attacker connects to the unauthenticated WebRTC-to-DDS bridge on port 9991.
3. The attacker retrieves the static AES-128 key from the device's world-readable local storage to decrypt or spoof control messages.
4. The attacker publishes crafted DDS control messages designed to restart the bashrunner service.
5. The attacker exploits a path traversal vulnerability in the chat_go knowledge upload API to upload a malicious binary or script.
6. The payload is placed into the bashrunner script execution directory through the directory traversal.
7. The attacker triggers the bashrunner service, which executes the injected payload.
8. The injected code executes as uid 0, granting the attacker full root access to the device.

## Impact

Successful exploitation results in full unauthenticated root access to the Unitree G1 EDU robot. This allows for total control over the robot's physical functions, potential data exfiltration, and the ability to persist within the environment. Given the nature of these robotic platforms, this impact extends to physical safety risks and total compromise of the robotic control system.

## Recommendation

* Apply the latest firmware updates provided by Unitree for G1 EDU units immediately to resolve the path traversal and authentication gaps.
* Restrict network access to TCP port 9991; this port should not be exposed to untrusted networks or the public internet.
* Audit filesystem permissions on affected devices to ensure cryptographic keys and sensitive configuration files are not world-readable.
* Implement network-level segmentation to isolate robotic hardware management interfaces from general-purpose network traffic.
