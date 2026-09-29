---
title: Multiple Critical Vulnerabilities in Anjvision YSSD-RTMP-H5 Firmware
slug: 2026-09-anjvision-yssd-rtmp-h5
description: Anjvision YSSD-RTMP-H5 firmware version 3.3.2.4_build_2024-12-26 contains multiple critical vulnerabilities, including command injection, hard-coded credentials, and lack of firmware signing, allowing remote unauthenticated attackers to gain full system control.
date: "2026-09-29T16:25:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - critical-infrastructure
  - remote-access
  - iot
  - vulnerability-disclosure
vendors:
  - Anjvision
products:
  - Anjvision YSSD-RTMP-H5 (firmware 3.3.2.4_build_2024-12-26)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Several ONVIF service endpoints process management requests without enforcing required authentication.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This could allow an unauthorized attacker to ... execute OS-level commands.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1542.001
    technique_name: 'Pre-OS Boot: System Firmware'
    evidence: This design allows an attacker who can reach the update routine to introduce untrusted firmware images that the device will accept as valid.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-272-05
  - https://www.cve.org/CVERecord?id=CVE-2026-100291
  - https://www.cve.org/CVERecord?id=CVE-2026-100292
  - https://www.cve.org/CVERecord?id=CVE-2026-100293
  - https://www.cve.org/CVERecord?id=CVE-2026-100294
  - https://www.cve.org/CVERecord?id=CVE-2026-100295
  - https://www.cve.org/CVERecord?id=CVE-2026-100296
  - https://www.cve.org/CVERecord?id=CVE-2026-100297
  - https://www.cve.org/CVERecord?id=CVE-2026-100298
  - https://www.cve.org/CVERecord?id=CVE-2026-100299
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate Anjvision YSSD-RTMP-H5 devices from the internet immediately due to confirmed critical RCE vulnerabilities and lack of vendor patch.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-100291, CVE-2026-100292
  mitigation_plan:
    - priority: immediate
      action: Implement network ACLs to block all management access to Anjvision devices from unauthorized subnets.
      owner: Network Security
      addresses: All listed CVEs
---

The Anjvision YSSD-RTMP-H5 device, commonly deployed in commercial facilities globally, contains multiple critical security vulnerabilities within firmware version 3.3.2.4_build_2024-12-26. These flaws, tracked as CVE-2026-100291 through CVE-2026-100299, collectively enable a range of malicious activities including unauthenticated access to device management, command injection, and firmware manipulation. The vulnerabilities stem from systemic security weaknesses such as insecure default configurations, lack of cryptographic verification for firmware updates, and the presence of hard-coded credentials and active debug interfaces. Anjvision has not provided a patch or remediation plan for these issues. Defenders should treat these devices as compromised if internet-exposed and prioritize network-level isolation or restrictive firewalling, as there is currently no path to secure the devices through vendor-provided updates.

## Impact

Successful exploitation of these vulnerabilities allows unauthenticated remote attackers to achieve OS-level command execution, intercept sensitive data, or fully take over the affected hardware. Given the deployment in commercial facilities, the impact includes potential loss of visibility, unauthorized control over physical security monitoring systems, and the ability to pivot into wider internal networks if the device is not properly segmented.

## Recommendation

- Implement strict network segmentation to ensure Anjvision YSSD-RTMP-H5 devices are not reachable from the public internet or untrusted network segments.
- Block all unsolicited inbound traffic to known management ports (e.g., ONVIF services) associated with these devices at the network perimeter.
- Audit outbound traffic from these devices to prevent potential exploitation of the identified SSRF vulnerability and unauthorized cloud service interaction.
- Given the lack of vendor-provided patches, consider phasing out these devices from production environments where data integrity or system availability is critical.
