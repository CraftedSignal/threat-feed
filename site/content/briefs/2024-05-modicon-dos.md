---
title: Schneider Electric Modicon PLC Denial-of-Service Vulnerability
slug: 2024-05-modicon-dos
description: Team82 disclosed vulnerabilities in Schneider Electric Modicon Controllers M241, M251, and M262 PLC lines, which can allow an attacker to cause a denial-of-service condition and affect controller availability.
date: "2026-03-23T19:15:23Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - plc
  - denial-of-service
  - industrial-control-system
  - modicon
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://www.reddit.com/r/netsec/comments/1s1qhra/vulnerability_disclosure_schneider_electric/
  - http://claroty.com/team82/disclosure-dashboard
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-069-01&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-069-01.pdf
iocs:
  - type: url
    value: http://claroty.com/team82/disclosure-dashboard
  - type: url
    value: https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-069-01&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-069-01.pdf
ioc_counts:
  url: 2
rules:
  - title: Possible Modbus DoS Attempt
    description: Detects a large number of Modbus requests to a PLC, which could indicate a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - zeek
  - title: Detect Multiple connections to Schneider Electric PLC on standard port
    description: Detects a high number of connections to port 502, the standard port for Modbus, which is used by Schneider Electric PLCs.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 23, 2026, Team82 disclosed vulnerabilities affecting Schneider Electric's Modicon M241, M251, and M262 programmable logic controllers (PLCs). These vulnerabilities, if exploited, can lead to a denial-of-service (DoS) condition, impacting the availability of the controller and potentially disrupting industrial processes. The Schneider Electric advisory SEVD-2026-069-01 addresses these issues, which were discovered by Claroty's Team82. Successful exploitation could halt critical operations controlled by these PLCs, affecting various industrial sectors that rely on Schneider Electric's automation solutions. Defenders should review the advisory and implement recommended mitigations to prevent potential disruptions.

## Attack Chain

Given the limited details in the source, the following attack chain is based on common PLC DoS attack vectors:

1. **Reconnaissance:** The attacker identifies a Modicon PLC M241/M251/M262 on the target network, potentially through network scanning or passive reconnaissance.
2. **Initial Access:** The attacker gains unauthorized access to the PLC's network, potentially through exploiting weak credentials, network misconfigurations, or vulnerabilities in related systems.
3. **Protocol Exploitation:** The attacker leverages a vulnerability in the Modbus or other industrial protocol used by the PLC for communication.
4. **Malicious Command Injection:** The attacker crafts and sends a series of specially crafted Modbus commands designed to overload the PLC's processing capabilities.
5. **Resource Exhaustion:** The PLC attempts to process the malicious commands, leading to excessive CPU utilization, memory exhaustion, or other resource depletion.
6. **Denial-of-Service:** The PLC becomes unresponsive and unable to execute its control logic, resulting in a denial-of-service condition. This affects the industrial process relying on the PLC.
7. **Process Disruption:** The industrial process controlled by the PLC halts or malfunctions due to the loss of control signals, leading to potential safety hazards, production losses, or equipment damage.

## Impact

Successful exploitation of these vulnerabilities results in a denial-of-service condition on the affected Schneider Electric Modicon PLCs. This can lead to disruption of industrial processes, potential equipment damage, and safety hazards. The exact impact depends on the specific application and the criticality of the controlled processes. Given the wide adoption of Modicon PLCs across various sectors, a successful attack could impact numerous organizations.

## Recommendation

*   Review Schneider Electric's advisory SEVD-2026-069-01 for detailed vulnerability information and recommended mitigations.
*   Implement network segmentation to isolate PLCs and other critical industrial control systems.
*   Monitor network traffic for suspicious Modbus commands or other anomalous communication patterns related to the Modicon PLCs using the provided Sigma rules.
*   Regularly audit and update PLC firmware to patch known vulnerabilities.
