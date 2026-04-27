---
title: Dell PowerProtect Data Domain BoostFS Credential Exposure Vulnerability (CVE-2025-36568)
slug: 2024-07-dell-powerprotect-credential-exposure
description: Dell PowerProtect Data Domain BoostFS versions 7.7.1.0 through 8.5, 8.3.1.0 through 8.3.1.20, and 7.13.1.0 through 7.13.1.50 are vulnerable to an insufficiently protected credentials vulnerability, allowing a low-privileged attacker with local access to expose credentials and potentially gain elevated privileges.
date: "2026-04-17T09:16:05Z"
severities:
  - high
tags:
  - credential-exposure
  - dell
  - powerprotect
  - CVE-2025-36568
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2025-36568
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-36568
rules:
  - title: Detect Suspicious Access to Dell PowerProtect BoostFS Credential Files
    description: Detects suspicious processes accessing credential-related files in Dell PowerProtect Data Domain BoostFS.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Process Execution from Dell PowerProtect BoostFS Directory
    description: Detects suspicious process execution from the Dell PowerProtect Data Domain BoostFS installation directory, which might indicate exploitation or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2025-36568 affects Dell PowerProtect Data Domain BoostFS for client software, specifically Feature Release versions 7.7.1.0 through 8.5, LTS2025 release versions 8.3.1.0 through 8.3.1.20, and LTS2024 release versions 7.13.1.0 through 7.13.1.50. The vulnerability stems from insufficiently protected credentials, potentially allowing a low-privileged attacker with local system access to expose sensitive information. Successful exploitation could allow the attacker to access the system with the…
