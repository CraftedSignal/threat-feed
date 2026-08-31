---
title: Critical Authentication Bypass in Tenda AC18 Telnet Handler
slug: 2026-08-tenda-telnet-bypass
description: A critical authentication bypass vulnerability in the Tenda AC18 router allows remote, unauthenticated attackers to gain unauthorized access via the Telnet service.
date: "2026-08-31T13:58:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:tenda:ac18_firmware:15.03.05.19:*:*:*:*:*:*:*
tags:
  - critical-infrastructure
  - network-security
  - authentication-bypass
vendors:
  - Tenda
products:
  - AC18 (15.03.05.19)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-82695
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82695
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict inbound Telnet access to Tenda devices via network edge firewall
      owner: SOC
      due: 24h
      evidence: CVE-2026-82695 allows unauthenticated remote access
  hunt_leads:
    - lead: Identify Tenda AC18 devices communicating on port 23 from external IP addresses
      technique_id: T1190
      data_needed:
        - Firewall logs
        - Netflow
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-82695 vulnerability description
  mitigation_plan:
    - priority: immediate
      action: Disable Telnet service on Tenda AC18 if not required
      owner: IT Operations
      addresses: CVE-2026-82695
      evidence: NVD description of Telnet Handler authentication bypass
---

CVE-2026-82695 identifies a critical security flaw in Tenda AC18 firmware version 15.03.05.19, residing in the Telnet Handler component. Specifically, the function located at /goform/telnet fails to perform proper authentication, permitting remote, unauthenticated actors to access the device's Telnet interface. This vulnerability is remotely exploitable and has been publicly disclosed with functional exploit code, posing a significant risk of device compromise. As the device provides management services, successful exploitation allows attackers to gain full administrative control over the network gateway, potentially enabling traffic interception, lateral movement, or use of the router as a botnet node. Defenders should assume that adversaries may use this as an initial access vector for further compromise of connected local networks.

## Impact

Successful exploitation of this vulnerability results in full administrative access to the Tenda AC18 device. This exposure impacts the confidentiality, integrity, and availability of all traffic routed through the affected device. Public availability of exploit code increases the likelihood of opportunistic scanning and mass-exploitation attempts by automated botnets targeting consumer and small-office network hardware.

## Recommendation

1. Immediately restrict access to the Tenda AC18 web management and Telnet interfaces to trusted management subnets only.
2. Monitor firewall logs for unauthorized connection attempts to port 23 (Telnet) on Tenda devices.
3. Search for firmware updates from the vendor; if no patch is available, replace the device or isolate it from public-facing segments.
4. Implement network-level segmentation to prevent the Tenda device from reaching internal critical assets.
