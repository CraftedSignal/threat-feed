---
title: Remote Stack-based Buffer Overflow in TRENDnet TV-IP751WIC
slug: 2026-08-trendnet-overflow
description: A critical stack-based buffer overflow vulnerability (CVE-2026-75877) in the TRENDnet TV-IP751WIC alphapd component allows remote attackers to execute arbitrary code via multiple affected functions.
date: "2026-08-18T21:00:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - TRENDnet
products:
  - TV-IP751WIC
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Executing a manipulation can lead to stack-based buffer overflow.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75877
  - https://vuldb.com/vuln/391571
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate all instances of TRENDnet TV-IP751WIC from internet exposure.
      owner: IT Operations
      due: 24h
      evidence: Critical CVSS score of 9.9 and public availability of exploit.
  hunt_leads:
    - lead: Search web logs for unusually long parameter values or shellcode-like strings directed at known alphapd functions.
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability triggers via manipulation of specific alphapd functions.
  mitigation_plan:
    - priority: immediate
      action: Disable remote management interface access.
      owner: IT Operations
      addresses: CVE-2026-75877
      evidence: Vulnerability is exploitable via remote manipulation of administrative functions.
---

A critical stack-based buffer overflow vulnerability has been identified in the TRENDnet TV-IP751WIC network camera, specifically within the 'alphapd' web server component. The vulnerability, tracked as CVE-2026-75877, affects firmware version 11.03.03. The issue stems from improper boundary management within several administrative and configuration functions, including SystemNetworkChanged, SystemDDNSChanged, SystemEmailChanged, SystemFTPChanged, and websCheckRealm. 

An attacker can trigger this overflow remotely by sending a specifically crafted request to these functions, leading to memory corruption. Because the 'alphapd' component runs as a core service, successful exploitation may allow for unauthenticated or low-privileged remote code execution. Proof-of-concept exploit code has been publicly released, increasing the risk of immediate exploitation. This vulnerability is particularly severe due to the remote, unauthenticated nature of the potential exploit chain and the administrative reach of the affected component.

## Attack Chain

1. Attacker performs network reconnaissance to identify internet-facing TRENDnet TV-IP751WIC devices.
2. Attacker probes the device to confirm the target firmware version (11.03.03).
3. Attacker crafts a malicious HTTP request targeting one of the identified vulnerable functions (e.g., SystemNetworkChanged).
4. Attacker includes an overly large payload within the request parameters to initiate a stack-based buffer overflow in the alphapd binary.
5. The alphapd service fails to validate input length, resulting in the overwrite of the return address on the stack.
6. The process redirects execution flow to the attacker-supplied shellcode embedded in the payload.
7. Attacker gains arbitrary code execution with the privileges of the alphapd process.
8. Attacker establishes persistence or pivots into the internal network from the compromised camera.

## Impact

The vulnerability carries a CVSS 3.1 base score of 9.9, representing a critical risk. Successful exploitation allows for complete compromise of the affected camera, leading to loss of confidentiality, integrity, and availability. Potential impacts include unauthorized access to video feeds, lateral movement into internal enterprise networks from the IoT device, and potential device bricking.

## Recommendation

* Immediately isolate all TRENDnet TV-IP751WIC devices from the public internet using firewalls or VPN requirements.
* Monitor internal network traffic originating from IoT segments for anomalous connections to or from these devices.
* Patch the affected devices if a firmware update is released by the vendor; prioritize decommissioning devices if no patch is available for the 11.03.03 version.
* Restrict administrative access to the web interface to trusted management VLANs only.
