---
title: Silex Technology SD-330AC and AMC Manager Insecure Default Password Vulnerability (CVE-2026-32965)
slug: 2026-04-silex-default-password
description: Silex Technology's SD-330AC and AMC Manager are vulnerable to insecure default initialization, allowing a null string password to be set upon initial network connection (CVE-2026-32965).
date: "2026-04-20T04:16:45Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-32965
  - default-password
  - silex-technology
cves:
  - id: CVE-2026-32965
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32965
  - https://jvn.jp/en/vu/JVNVU94271449/
  - https://www.silex.jp/support/security-advisories/2026-001
  - https://www.silex.jp/support/security-advisories/en/2026-001
rules:
  - title: Detect Silex Device Configuration Attempt with Empty Password
    description: Detects attempts to configure Silex SD-330AC or AMC Manager devices with an empty password string, indicating potential exploitation of CVE-2026-32965.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Silex Device Management Interface Access
    description: Detects access to the Silex SD-330AC or AMC Manager device management interface which could be an attempt to configure the device with an empty password string, indicating potential exploitation of CVE-2026-32965.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-32965 describes a vulnerability in Silex Technology's SD-330AC and AMC Manager. When a device is connected to a network with its factory-default configuration, it can be configured with a null string password, essentially leaving it unprotected. This vulnerability was reported by JPCERT/CC. The advisory highlights that an attacker could potentially exploit this misconfiguration to gain unauthorized access to the affected devices and their associated networks. This poses a risk of data compromise, device hijacking, and further lateral movement within the network. Defenders should prioritize identifying and remediating instances of these devices using default configurations on their networks.

## Attack Chain

1.  An affected Silex Technology SD-330AC or AMC Manager device is connected to a network with its factory-default configuration.
2.  An attacker identifies the device on the network, potentially through network scanning.
3.  The attacker attempts to access the device's configuration interface via a web browser or other management tool.
4.  The attacker provides a null string as the password during authentication.
5.  The device accepts the null string as a valid password due to the insecure default initialization.
6.  The attacker gains unauthorized access to the device's configuration settings.
7.  The attacker modifies device settings, potentially disrupting services or gaining further access to the network.

## Impact

Successful exploitation of CVE-2026-32965 allows an attacker to gain unauthorized access to Silex Technology SD-330AC and AMC Manager devices. This could lead to a compromise of sensitive data handled by the device or allow the attacker to use the device as a pivot point for further attacks within the network. The impact is significant because it provides a straightforward entry point without requiring sophisticated exploitation techniques. While the number of affected devices is unknown, organizations using these products should immediately assess their exposure and implement mitigation measures.

## Recommendation

*   Identify all instances of Silex Technology SD-330AC and AMC Manager devices on your network and verify their configuration.
*   Enforce a policy requiring strong, unique passwords for all network devices, especially those with default configurations.
*   Deploy the Sigma rule `Detect Silex Device Configuration Attempt with Empty Password` to identify attempts to configure the device with a null string password.
*   Consult Silex Technology's security advisory [https://www.silex.jp/support/security-advisories/2026-001](https://www.silex.jp/support/security-advisories/2026-001) for specific remediation steps and firmware updates.
