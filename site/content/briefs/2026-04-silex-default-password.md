---
title: Silex Technology SD-330AC and AMC Manager Insecure Default Password Vulnerability (CVE-2026-32965)
slug: 2026-04-silex-default-password
description: Silex Technology's SD-330AC and AMC Manager are vulnerable to insecure default initialization, allowing a null string password to be set upon initial network connection (CVE-2026-32965).
date: "2026-04-20T04:16:45Z"
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

CVE-2026-32965 describes a vulnerability in Silex Technology's SD-330AC and AMC Manager. When a device is connected to a network with its factory-default configuration, it can be configured with a null string password, essentially leaving it unprotected. This vulnerability was reported by JPCERT/CC. The advisory highlights that an attacker could potentially exploit this misconfiguration to gain unauthorized access to the affected devices and their associated networks. This poses a risk of data…
