---
title: Remote Buffer Overflow in Tenda AC12 Web Management Interface
slug: 2026-08-tenda-ac12-overflow
description: Tenda AC12 router firmware contains a buffer overflow vulnerability in the httpd web management interface, allowing remote attackers to trigger arbitrary code execution via a manipulated reboot parameter.
date: "2026-08-14T12:07:56Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Tenda
products:
  - AC12 (15.03.06.23_multi_TD01)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19821
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19821
  - https://github.com/lipenghai/iot_bug/blob/main/Tenda/AC12/4.md
  - https://vuldb.com/vuln/389954
rules:
  - title: Detects CVE-2026-19821 Exploitation - Unauthorized Access Attempt
    description: Detects potential exploitation attempts of CVE-2026-19821 by monitoring for POST requests to the vulnerable reboot configuration endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule for /goform/SetSysAutoRebbotCfg access
      owner: Detection Engineering
      due: 48h
      evidence: Exploit publicly available for CVE-2026-19821
  mitigation_plan:
    - priority: immediate
      action: Restrict web management interface access
      owner: IT Operations
      addresses: CVE-2026-19821
      evidence: NVD vulnerability disclosure
---

A remote buffer overflow vulnerability (CVE-2026-19821) exists in the Tenda AC12 router running firmware version 15.03.06.23_multi_TD01. The vulnerability originates within the 'formSetRebootTimer' function of the '/goform/SetSysAutoRebbotCfg' file, which is part of the device's httpd web management interface. By sending a maliciously crafted 'rebootTime' argument, an authenticated remote attacker can cause a buffer overflow, potentially leading to arbitrary code execution or device instability. The vulnerability has been publicly disclosed with functional exploit code available, posing a significant risk to devices accessible over the network. Defenders should prioritize restricting access to the management interface and monitoring for anomalous HTTP requests targeting the reboot configuration endpoint.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code with the privileges of the web management service. This can lead to a full device compromise, enabling attackers to gain persistence, intercept network traffic, or use the router as a pivot point for further lateral movement within the local network. Given the router's role as a network gateway, this represents a critical threat to the security and integrity of connected residential or small-office environments.

## Recommendation

- Implement network-level segmentation to restrict access to the Tenda AC12 web management interface to trusted administrative IPs only.
- Deploy detection rules to monitor web server logs for anomalous POST requests to the /goform/SetSysAutoRebbotCfg endpoint.
- Disable remote web management access on the router immediately if not required.
- Check for and apply firmware updates from the vendor if they become available to address CVE-2026-19821.
