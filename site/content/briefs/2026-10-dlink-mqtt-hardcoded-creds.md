---
title: Hard-Coded Credentials in D-Link MQTT Broker
slug: 2026-10-dlink-mqtt-hardcoded-creds
description: Multiple D-Link router models contain hard-coded credentials in the MQTT Broker component, allowing for potential remote unauthorized access via public exploit code.
date: "2026-10-19T16:08:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - hardware
  - router
  - vulnerability
  - remote-access
vendors:
  - D-Link
products:
  - E15
  - M32
  - R15
  - R32
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsafe Credential Material
    evidence: The manipulation results in hard-coded credentials.
    confidence_band: high
cves:
  - id: CVE-2026-112146
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112146
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict internet exposure of affected D-Link MQTT interfaces
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is remotely exploitable
  mitigation_plan:
    - priority: immediate
      action: Apply vendor firmware patches for D-Link E15, M32, R15, and R32
      owner: IT Operations
      addresses: CVE-2026-112146
      evidence: NVD advisory
---

A security vulnerability identified as CVE-2026-112146 affects several D-Link router models, including the E15, M32, R15, and R32. The vulnerability resides within the MQTT Broker component, which improperly manages or exposes credentials stored in the '/etc/emDaemon/passwd' file. This flaw involves the use of hard-coded credentials that can be leveraged by an attacker to gain unauthorized access to the device. The vulnerability is exploitable remotely, and because exploit code has been made publicly available, there is an increased risk of automated or manual exploitation attempts against exposed devices. Defenders should prioritize identifying these specific D-Link models on their networks and isolating them from external access if patching or mitigation is not immediately possible.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing D-Link devices running the vulnerable MQTT Broker component.
2. Attacker initiates a network connection to the target device, targeting the MQTT service port.
3. Attacker uses publicly available exploit code to interface with the MQTT Broker component.
4. Attacker targets the '/etc/emDaemon/passwd' file processing logic via the discovered vulnerability.
5. Attacker authenticates to the device using the hard-coded credentials recovered or utilized by the exploit.
6. Attacker establishes an unauthorized session to perform configuration changes or exfiltrate device information.

## Impact

The vulnerability allows unauthenticated, remote attackers to obtain unauthorized access to D-Link E15, M32, R15, and R32 routers. Successful exploitation could lead to full device compromise, allowing attackers to manipulate network traffic, intercept data, or pivot into internal network segments, potentially affecting the integrity and confidentiality of the entire local area network connected to these devices.

## Recommendation

* Review network egress and ingress logs for unauthorized traffic targeting MQTT service ports associated with D-Link devices.
* Restrict external access to the management interface and MQTT broker ports of the affected D-Link models immediately.
* Consult the D-Link support portal for the latest firmware updates that resolve CVE-2026-112146 for the affected E15, M32, R15, and R32 models and apply them.
