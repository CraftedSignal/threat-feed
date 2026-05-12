---
title: KACO blueplanet Devices Vulnerable to Credential Derivation (CVE-2025-40946)
slug: 2026-05-kaco-credential-disclosure
description: CVE-2025-40946 describes a vulnerability in KACO new energy blueplanet products where a weak CRC16-based algorithm for generating Technical Service credentials could allow an attacker to derive the credentials from the device's serial number and misuse them to gain unauthorized access.
date: "2026-05-12T10:19:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - vulnerability
  - KACO
vendors:
  - KACO new energy
products:
  - blueplanet 100 NX3 M8
  - blueplanet 100 TL3 GEN2
  - blueplanet 105 TL3
  - blueplanet 105 TL3 GEN2
  - blueplanet 110 TL3
  - blueplanet 125 NX3 M11
  - blueplanet 125 TL3
  - blueplanet 125 TL3 GEN2
  - blueplanet 137 TL3
  - blueplanet 150 TL3
  - blueplanet 150 TL3 GEN2
  - blueplanet 155 TL3
  - blueplanet 155 TL3 GEN2
  - blueplanet 165 TL3
  - blueplanet 165 TL3 GEN2
  - blueplanet 25.0 NX3-33.0 NX3
  - blueplanet 3.0 NX3-20.0 NX3
  - blueplanet 3.0 TL3-60.0 TL3
  - blueplanet 3.0-5.0 NX1
  - blueplanet 360 NX3 M6
  - blueplanet 50.0 NX3-60.0 NX3
  - blueplanet 87.0 TL3
  - blueplanet 87.0 TL3 GEN2
  - blueplanet 92.0 TL3
  - blueplanet 92.0 TL3 GEN2
  - blueplanet gridsafe 110 TL3-S
  - blueplanet gridsafe 137 TL3-S
  - blueplanet gridsafe 92.0 TL3-S
  - blueplanet hybrid 10.0 TL3
  - blueplanet hybrid 6.0 NH3-12.0 NH3
cves:
  - id: CVE-2025-40946
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-40946
rules:
  - title: Detect Technical Service Login Attempts to BluePlanet Devices
    description: Detects potential brute-force or unauthorized login attempts to KACO BluePlanet devices based on abnormal authentication failure counts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
  - title: Detect CVE-2025-40946 Exploitation Attempts - Technical Service Credential Use
    description: Detects CVE-2025-40946 exploitation attempts by monitoring for successful logins using derived Technical Service credentials after device information retrieval. This requires correlated logs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - cve-2025-40946
    techniques:
      - T1110
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability, CVE-2025-40946, exists in KACO new energy's blueplanet product line. The affected products include a wide range of inverters and energy storage systems, such as blueplanet 100 NX3 M8, blueplanet 100 TL3 GEN2 (All versions < V6.1.4.9), and blueplanet gridsafe models. The vulnerability stems from a weak CRC16-based algorithm used to generate Technical Service credentials. An attacker with knowledge of this algorithm and a device's serial number could derive valid credentials, leading to unauthorized access and control over the affected device. This is significant as it allows unauthorized modification of system settings, potential disruption of energy production, and possible lateral movement within a network if the device is interconnected with other systems.

## Attack Chain

1.  Attacker gains knowledge of the CRC16-based algorithm used to generate Technical Service credentials.
2.  Attacker obtains the serial number of a vulnerable KACO blueplanet device (e.g., through physical access, network scanning, or publicly available information).
3.  Attacker inputs the device serial number into a custom script or tool implementing the known CRC16 algorithm.
4.  The script calculates the Technical Service credentials based on the serial number and the flawed algorithm.
5.  Attacker uses the derived credentials to authenticate to the device's web interface or API.
6.  Upon successful authentication, the attacker gains unauthorized access to device settings and functionality.
7.  Attacker modifies configuration settings, such as grid parameters, communication protocols, or firmware update settings.
8.  The attacker could disrupt energy production, cause grid instability, or use the compromised device as a foothold for further attacks within the network.

## Impact

Successful exploitation of CVE-2025-40946 allows an attacker to gain unauthorized access to KACO blueplanet devices. This can lead to a variety of impacts, including disruption of energy production, manipulation of grid parameters leading to potential grid instability, and the use of compromised devices as entry points for further attacks within a network. The wide range of affected devices increases the potential scope of impact, especially within organizations heavily reliant on KACO's blueplanet series for energy management.

## Recommendation

*   Upgrade blueplanet 100 TL3 GEN2, blueplanet 105 TL3 GEN2, blueplanet 125 TL3 GEN2, blueplanet 150 TL3 GEN2, blueplanet 155 TL3 GEN2, blueplanet 165 TL3 GEN2, blueplanet 87.0 TL3 GEN2, blueplanet 92.0 TL3 GEN2 to version V6.1.4.9 or later to remediate CVE-2025-40946.
*   Upgrade blueplanet gridsafe 110 TL3-S, blueplanet gridsafe 137 TL3-S, blueplanet gridsafe 92.0 TL3-S to version V3.91 or later to remediate CVE-2025-40946.
*   Monitor network traffic for suspicious authentication attempts to KACO blueplanet devices, especially from unusual source IPs or during off-peak hours. Create firewall rules based on network_connection logs.
*   Implement multi-factor authentication for all device access to mitigate credential-based attacks.
