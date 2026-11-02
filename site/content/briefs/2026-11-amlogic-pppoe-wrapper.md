---
brief_id: brief-2026-11-02-amlogic-pppoe-wrapper
event_id: brief-2026-11-02-amlogic-pppoe-wrapper
revision: 1
activity_at: "2026-11-02T21:52:04Z"
title: 'Amlogic Android SDK: pppoe_wrapper root command injection (CVE-2026-119737)'
slug: 2026-11-amlogic-pppoe-wrapper
description: A command injection vulnerability in the pppoe_wrapper daemon on Amlogic-based Android TV boxes allows local attackers to achieve root privilege escalation by sending malicious payloads to a world-writable AF_UNIX socket.
date: "2026-11-02T21:52:04Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:amlogic:android_sdk:*:*:*:*:*:*:*:*
vendors:
  - Amlogic
  - Nexbox
products:
  - Android SDK
  - A95X
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can send a message beginning with pppd pty followed by shell metacharacters and arbitrary commands, which are passed unfiltered to system(3) and executed by /system/bin/sh -c as root, resulting in full privilege escalation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Attackers can send a message beginning with pppd pty followed by shell metacharacters and arbitrary commands, which are passed unfiltered to system(3) and executed by /system/bin/sh -c as root.
    confidence_band: high
cves:
  - id: CVE-2026-119737
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119737
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit environment for the existence of /dev/socket/pppoe_wrapper
      owner: IT Operations
      due: 48h
      evidence: Vulnerability occurs via the world-writable AF_UNIX datagram socket at /dev/socket/pppoe_wrapper
  hunt_leads:
    - lead: Monitor for suspicious processes spawned by the pppoe_wrapper process or unexpected root shells
      technique_id: T1068
      data_needed:
        - Auditd or process accounting logs identifying pppoe_wrapper as the parent process
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The daemon executes commands via system(3) using the user-controlled input
---

The pppoe_wrapper vendor daemon within the Amlogic Android SDK, utilized in devices such as the Nexbox A95X (Amlogic S905/S905X), is vulnerable to command injection. An attacker with local access can interact with a world-writable AF_UNIX datagram socket located at /dev/socket/pppoe_wrapper. By crafting a message starting with 'pppd pty' followed by shell metacharacters, the input is passed to system(3) and executed with root privileges via /system/bin/sh -c. This results in full system compromise. No patch information is currently provided.

## Impact

Successful exploitation results in full root privilege escalation on the affected Android device.

## Recommendation

Identify and audit devices running the Amlogic Android SDK for the presence of the world-writable /dev/socket/pppoe_wrapper socket. If the service is not required for production functionality, disable the pppoe_wrapper daemon or restrict access permissions to the socket file if the underlying operating system and hardware configuration permit.
