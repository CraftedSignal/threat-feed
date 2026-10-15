---
title: Buffer Overflow in SODOLA SL902-SWTGW124AS Firmware
slug: 2026-10-sodola-buffer-overflow
description: An unauthenticated buffer overflow vulnerability in the SODOLA SL902-SWTGW124AS embedded HTTP server allows remote attackers to cause a denial of service via oversized multipart/form-data headers.
date: "2026-10-15T02:34:15Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:sodola:sl902-swtgw124as_firmware:*:*:*:*:*:*:*:*
vendors:
  - SODOLA
products:
  - SL902-SWTGW124AS (< 200.2.12)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This vulnerability allows an unauthenticated remote attacker to trigger a denial of service, causing the device to stop forwarding traffic and lose management access.
    confidence_band: high
cves:
  - id: CVE-2026-0993
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-0993
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Engineering
  immediate_actions:
    - action: Upgrade SODOLA SL902-SWTGW124AS firmware to 200.2.12
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-0993 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface access via ACLs
      owner: Network Engineering
      addresses: CVE-2026-0993
      evidence: Unauthenticated remote access is required for exploitation
---

The SODOLA SL902-SWTGW124AS network switch utilizes an embedded HTTP server that fails to properly validate the length of boundary values within the Content-Type header of multipart/form-data POST requests. This memory corruption vulnerability, identified as CVE-2026-0993, allows an unauthenticated remote attacker to trigger a buffer overflow by supplying an excessively large boundary string. Successful exploitation leads to a denial of service (DoS) state, where the device becomes unresponsive, ceases traffic forwarding, and terminates management access while it undergoes a self-recovery cycle. This vulnerability impacts all firmware versions prior to 200.2.12. Given the nature of network infrastructure devices, this threat poses a significant risk to network availability in environments where these switches are deployed.

## Impact

The vulnerability directly targets the availability of network switches within the victim infrastructure. Successful exploitation forces a device reboot or hung state, resulting in complete loss of network connectivity and management capabilities for the impacted segment during the recovery period. This impact is significant for industrial or enterprise environments relying on these switches for critical traffic routing and device communication.

## Recommendation

- Upgrade the firmware of all SODOLA SL902-SWTGW124AS devices to version 200.2.12 or later to address CVE-2026-0993.
- Restrict access to the management interface of network switches to trusted administrative IP ranges via firewall rules or access control lists.
- Implement monitoring on network infrastructure devices to detect anomalous, high-frequency HTTP traffic or unexpected device restarts (via SNMP or syslog) that may indicate DoS attempts.
