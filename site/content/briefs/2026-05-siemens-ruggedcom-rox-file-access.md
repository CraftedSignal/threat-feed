---
title: Siemens Ruggedcom Rox Improper Access Control Vulnerability
slug: 2026-05-siemens-ruggedcom-rox-file-access
description: Siemens Ruggedcom Rox is vulnerable to improper access control, allowing an authenticated remote attacker to read arbitrary files with root privileges from the underlying operating system's filesystem via the web server's JSON-RPC interface, as tracked by CVE-2025-40948.
date: "2026-05-14T15:03:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - siemens
  - ruggedcom
  - ics
  - file-access
  - attack.credential_access
vendors:
  - Siemens
products:
  - RUGGEDCOM ROX MX5000
  - RUGGEDCOM ROX MX5000RE
  - RUGGEDCOM ROX RX1400
  - RUGGEDCOM ROX RX1500
  - RUGGEDCOM ROX RX1501
  - RUGGEDCOM ROX RX1510
  - RUGGEDCOM ROX RX1511
  - RUGGEDCOM ROX RX1512
  - RUGGEDCOM ROX RX1524
  - RUGGEDCOM ROX RX1536
  - RUGGEDCOM ROX RX5000
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2025-40948
    cvss: 6.8
    epss: 0.00037
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02
  - https://www.cve.org/CVERecord?id=CVE-2025-40948
  - https://support.industry.siemens.com/cs/ww/en/view/110002017/
rules:
  - title: Detect CVE-2025-40948 Exploitation Attempt via JSON-RPC
    description: Detects CVE-2025-40948 exploitation attempt - Suspicious JSON-RPC requests to Siemens Ruggedcom Rox devices indicating potential file access attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - webserver
  - title: Detect CVE-2025-40948 Exploitation Attempt via JSON-RPC POST
    description: Detects CVE-2025-40948 exploitation attempt - Suspicious JSON-RPC POST requests to Siemens Ruggedcom Rox devices indicating potential file access attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - webserver
rules_count: 2
---

Siemens Ruggedcom Rox devices are affected by an improper access control vulnerability within the web server's JSON-RPC interface. This flaw, identified as CVE-2025-40948, could allow an authenticated remote attacker to read arbitrary files with root privileges from the underlying operating system's filesystem. The affected products include RUGGEDCOM ROX MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536, and RX5000 versions prior to 2.17.1. This vulnerability poses a significant risk to critical infrastructure sectors, particularly critical manufacturing, where these devices are commonly deployed worldwide. Successful exploitation could lead to unauthorized access to sensitive system files and potentially compromise the integrity and availability of industrial control systems.

## Attack Chain

1.  The attacker gains authenticated access to the Ruggedcom Rox device's web interface. This could be achieved through stolen credentials, default credentials, or other authentication bypass vulnerabilities.
2.  The attacker crafts a malicious JSON-RPC request targeting the vulnerable endpoint. This request includes a payload designed to exploit the improper input validation.
3.  The malicious JSON-RPC request is sent to the device's web server.
4.  The web server processes the request without properly validating the input, allowing the attacker to specify arbitrary file paths.
5.  The device attempts to access the specified file path with root privileges.
6.  The device reads the contents of the file and returns them to the attacker.
7.  The attacker gains access to sensitive system information, configuration files, or other critical data.

## Impact

Successful exploitation of CVE-2025-40948 allows an authenticated remote attacker to read arbitrary files with root privileges from the underlying operating system's filesystem on affected Siemens Ruggedcom Rox devices. This could enable the attacker to gain access to sensitive information, such as configuration files, credentials, or other critical data, potentially leading to further compromise of the industrial control system. The vulnerability affects a wide range of Ruggedcom Rox devices, impacting critical infrastructure sectors, particularly critical manufacturing.

## Recommendation

*   Apply the vendor-supplied patch to upgrade to version 2.17.1 or later to remediate CVE-2025-40948.
*   Deploy the Sigma rule "Detect CVE-2025-40948 Exploitation Attempt via JSON-RPC" to identify potential exploitation attempts.
*   Monitor webserver logs for unusual JSON-RPC requests targeting the Ruggedcom Rox devices.
