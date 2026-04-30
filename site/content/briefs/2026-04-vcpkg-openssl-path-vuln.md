---
title: vcpkg OpenSSL Windows Build Path Vulnerability (CVE-2026-34054)
slug: 2026-04-vcpkg-openssl-path-vuln
description: A vulnerability exists in vcpkg versions prior to 3.6.1#3, where Windows builds of OpenSSL set openssldir to a path on the build machine, making that path vulnerable to attack on customer machines.
date: "2026-03-31T03:20:08Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - vulnerability
  - openssl
  - vcpkg
  - cwe-427
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-34054
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34054
  - https://github.com/microsoft/vcpkg/commit/5111afdf55cc1429d9951e4c7b02010e659346a9
  - https://github.com/microsoft/vcpkg/pull/50518
  - https://github.com/microsoft/vcpkg/security/advisories/GHSA-p322-v6vw-vrq9
rules:
  - title: Detect OpenSSL loading from non-standard path
    description: Detects when OpenSSL libraries are loaded from a non-standard path, which might indicate exploitation of CVE-2026-34054
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - image_load
      - windows
  - title: Detect modification of OpenSSL config directory
    description: Detects modification events within the OpenSSL configuration directory, potentially indicating malicious activity related to CVE-2026-34054.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The vcpkg is a free and open-source C/C++ package manager. Prior to version 3.6.1#3, vcpkg's Windows builds of OpenSSL configured the `openssldir` setting to a path specific to the build machine. This configuration error means that when the built OpenSSL binaries are deployed to customer machines, the `openssldir` value still points to a location on the original build system. This creates a vulnerability, because attackers could potentially manipulate or replace files in this directory on the…
