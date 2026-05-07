---
title: Moxa Security Advisory Addresses Vulnerabilities in Multiple Router Series
slug: 2026-04-moxa-router-vulns
description: Moxa released a security advisory addressing CVE-2026-3867 and CVE-2026-3868, which affect TN-4900, EDR-8010, EDR-G9010, OnCell G4302-LTE4, OnCell G4308-LTE4, and EDF-G1002-BP series routers, potentially allowing for unauthorized access and control.
date: "2026-04-27T14:42:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - router
  - industrial-control-systems
vendors:
  - Moxa
products:
  - TN-4900 Series
  - EDR-8010 Series
  - EDR-G9010 Series
  - OnCell G4302-LTE4 Series
  - OnCell G4308-LTE4 Series
  - EDF-G1002-BP Series
cves:
  - id: CVE-2026-3867
    epss: 0.00043
  - id: CVE-2026-3868
    epss: 0.00114
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-moxa-security-advisory-av26-393
  - https://www.moxa.com/en/support/product-support/security-advisory/mpsa-261521-cve-2026-3867-cve-2026-3868-improper-ownership-management-and-improper-handling-of-length-parameter-incons
  - https://www.moxa.com/en/support/product-support/security-advisory
rules:
  - title: Detect Suspicious Outbound Connection from Moxa Router
    description: Detects potentially malicious outbound connections initiated from Moxa routers after exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Detect File Modification on Moxa Routers
    description: Detects unauthorized modifications to system files on Moxa routers, potentially indicative of CVE-2026-3867 exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect Moxa Router Firmware Upgrade Attempt via TFTP
    description: Detects suspicious TFTP activity that may indicate an attempt to upgrade router firmware using TFTP
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1195
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

On April 27, 2026, Moxa published a security advisory (MPSA-261521) to address vulnerabilities, specifically CVE-2026-3867 and CVE-2026-3868, affecting several of their industrial router products. These vulnerabilities reside in the firmware of TN-4900 Series (firmware version v3.22 and prior), EDR-8010 Series (firmware version v3.23 and prior), EDR-G9010 Series (firmware version v3.23.1 and prior), OnCell G4302-LTE4 Series (firmware version v3.23.0 and prior), OnCell G4308-LTE4 Series (firmware version v3.23.0 and prior), and EDF-G1002-BP Series (firmware version v3.23 and prior). Successful exploitation could allow attackers to gain unauthorized access or control over affected devices, potentially disrupting industrial processes and critical infrastructure. Defenders should promptly apply the recommended updates to mitigate the risk.

## Attack Chain

1. An attacker identifies a vulnerable Moxa router, such as a TN-4900 series running firmware v3.22 or prior.
2. The attacker exploits CVE-2026-3867 (Improper Ownership Management) to manipulate file permissions on the device.
3. Exploiting the improper file ownership, the attacker overwrites critical system files with malicious versions.
4. The attacker exploits CVE-2026-3868 (Improper Handling of Length Parameter Inconsistency) to trigger a buffer overflow.
5. The buffer overflow allows the attacker to inject arbitrary code into the running system process.
6. The injected code provides the attacker with a reverse shell to the device with elevated privileges.
7. The attacker uses the reverse shell to gain full control over the router, modifying configurations and potentially disrupting network operations.
8. Finally, the attacker pivots to other devices on the network, using the compromised router as a launchpad for further attacks within the industrial control system (ICS) network.

## Impact

Successful exploitation of these vulnerabilities could allow unauthorized access and control of the affected Moxa routers. In industrial environments, this can lead to disruption of critical services, manipulation of industrial processes, and potential physical damage to equipment. Given the widespread use of Moxa devices in various sectors, including manufacturing, transportation, and energy, a successful attack could have significant consequences. The impact would vary depending on the specific industrial process controlled by the affected router, but could potentially affect dozens of organizations and even critical infrastructure.

## Recommendation

*   Immediately patch all affected Moxa devices (TN-4900, EDR-8010, EDR-G9010, OnCell G4302-LTE4, OnCell G4308-LTE4, and EDF-G1002-BP Series) to the latest firmware versions as recommended in the Moxa security advisory.
*   Monitor network traffic for unusual patterns or connections originating from Moxa routers, indicative of potential exploitation, by deploying the "Detect Suspicious Outbound Connection from Moxa Router" Sigma rule.
*   Implement strict access control policies to limit access to Moxa devices and segment the network to prevent lateral movement in case of a compromise.
