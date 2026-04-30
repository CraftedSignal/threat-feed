---
title: OpenPrinting CUPS Path Traversal Vulnerability (CVE-2026-34978)
slug: 2026-05-cups-path-traversal
description: CVE-2026-34978 is a path traversal vulnerability in OpenPrinting CUPS that allows writing files outside the CacheDir/rss directory, potentially overwriting the job.cache file.
date: "2026-04-30T08:46:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path traversal
  - cups
  - cve-2026-34978
  - file write
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-34978
    cvss: 6.5
    epss: 0.00076
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-34978
rules:
  - title: Detect CUPS Path Traversal File Write
    description: Detects potential path traversal attempts in CUPS by monitoring for file writes outside of the intended CacheDir/rss directory.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - file_event
      - linux
  - title: Detect CUPS job.cache Overwrite
    description: Detects attempts to overwrite the CUPS job.cache file, potentially indicating exploitation of CVE-2026-34978.
    platform: sigma
    severity: critical
    tactics:
      - availability
    techniques:
      - T1485
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-34978 is a path traversal vulnerability affecting OpenPrinting CUPS, a modular printing system that allows a computer to act as a print server. The vulnerability exists within the RSS notify-recipient-uri functionality, which improperly validates file paths. By crafting a malicious URI, an attacker can write files outside the intended CacheDir/rss directory. This can lead to the overwriting of critical system files, such as job.cache, potentially disrupting print services and, in some scenarios, leading to arbitrary code execution. This vulnerability was disclosed by Microsoft and requires immediate attention from system administrators to prevent potential exploitation.

## Attack Chain

1. An attacker crafts a malicious RSS notify-recipient-uri containing a path traversal sequence (e.g., "../").
2. The crafted URI is submitted to the CUPS server through a print job request or a configuration setting.
3. CUPS processes the URI and attempts to write a file to the specified location.
4. Due to the path traversal vulnerability, the file is written outside the intended CacheDir/rss directory.
5. The attacker overwrites a critical file, such as job.cache, with malicious content.
6. The CUPS server attempts to access the overwritten file.
7. If job.cache is successfully overwritten, the attacker can gain control of the print queue or cause a denial of service by corrupting the print system's state.
8. In a more advanced scenario, the attacker could potentially achieve arbitrary code execution by overwriting other binaries or configuration files.

## Impact

Successful exploitation of CVE-2026-34978 can lead to denial of service by corrupting the printing system state. By overwriting critical CUPS files, an attacker can disrupt printing services. In more critical scenarios, the vulnerability could be leveraged to achieve arbitrary code execution, potentially allowing the attacker to gain complete control over the affected system. The scope of the impact is dependent on the permissions of the CUPS process and the specific files that are overwritten.

## Recommendation

*   Apply the security patch provided by OpenPrinting to address CVE-2026-34978.
*   Monitor CUPS server logs for suspicious activity related to file writes outside the CacheDir/rss directory. Consider deploying the provided Sigma rule `Detect CUPS Path Traversal File Write` to identify such attempts.
*   Implement strict input validation on any user-supplied data that is used to construct file paths within CUPS.
*   Regularly review and audit CUPS configuration settings to ensure that they are secure and do not allow for path traversal vulnerabilities.
