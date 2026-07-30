---
title: Unauthenticated Remote Access to Phoenix Contact CHARX SEC MQTT Broker
slug: 2026-07-mqtt-auth-bypass
description: A critical vulnerability (CVE-2026-44090) in Phoenix Contact CHARX SEC controllers allows unauthenticated remote attackers to gain full device control by bypassing authentication on the MQTT broker.
date: "2026-07-30T08:12:15Z"
lastmod: "2026-07-30T08:12:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - industrial-control-systems
  - mqtt
  - cve-2026-44091
vendors:
  - Phoenix Contact
products:
  - CHARX SEC-3150
  - CHARX SEC-3100
  - CHARX SEC-3050
  - CHARX SEC-3000
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can post a malicious ID to the MQTT Broker results in the creation of a new configuration entry.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: results in the creation of a new configuration entry in the system configuration.
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This may lead to integrity and availability loss.
    confidence_band: high
cves:
  - id: CVE-2026-44090
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44090
  - https://www.certvde.com/en/advisories/VDE-2026-008/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44091
rules:
  - title: Detect Unauthorized MQTT Connection to Phoenix CHARX Controllers
    description: Detects potential exploitation of CVE-2026-44090 by identifying unauthenticated MQTT connection attempts directed at known controller ports.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
rules_count: 1
updates:
  - at: "2026-07-30T08:12:28Z"
    level: L1
    summary: 'merged source coverage: Unauthenticated Configuration Injection in Phoenix Contact CHARX Controllers'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-44091
---

Phoenix Contact has disclosed a critical security vulnerability, CVE-2026-44090, affecting its CHARX SEC series controllers. The vulnerability stems from a missing authentication mechanism within the onboard MQTT broker, which handles message queuing and device communication. Because the broker lacks required authentication, an unauthenticated remote attacker with network reach to the device can interface directly with the broker. While these devices are typically intended to be protected by external firewalls, the absence of internal authentication means that any misconfiguration or firewall bypass permits full unauthorized command execution and device compromise. The vulnerability affects firmware versions prior to 1.9.1. Organizations utilizing these controllers in industrial or EV charging infrastructure should prioritize upgrading to firmware version 1.9.1 or later and verify that network exposure is strictly limited.

## Attack Chain

1. Attacker performs network reconnaissance to identify exposed CHARX SEC controllers (e.g., scanning for open ports associated with MQTT).
2. Attacker bypasses perimeter firewall protections if the device is misconfigured or exposed via port forwarding.
3. Attacker establishes a TCP connection to the MQTT broker port (typically 1883 or 8883) on the target controller.
4. Attacker transmits unauthenticated MQTT control packets to the broker.
5. The broker, lacking authentication, accepts the connection and processes the malicious commands.
6. Attacker leverages MQTT topics to send commands to internal device functions or application-layer services.
7. The device executes the commands with high-level privileges, leading to a full system compromise.

## Impact

Successful exploitation of CVE-2026-44090 results in full compromise of the CHARX SEC controller. This can lead to unauthorized control over industrial or charging processes, loss of operational integrity, and potential lateral movement into the wider industrial control network. The impact is assessed as high across confidentiality, integrity, and availability (CVSS 9.8).

## Recommendation

1. Upgrade all affected Phoenix Contact CHARX SEC controllers to firmware version 1.9.1 or later immediately.
2. Audit firewall configurations to ensure that the MQTT broker ports are not exposed to untrusted networks.
3. Implement network segmentation to ensure that only authorized services can reach the MQTT broker interface on industrial controllers.
4. Deploy network-based intrusion detection signatures to identify unauthorized MQTT traffic patterns targeting the specific CHARX SEC devices in the environment.
