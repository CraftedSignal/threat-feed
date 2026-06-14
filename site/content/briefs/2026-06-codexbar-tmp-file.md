---
title: CodexBar Insecure Temporary File Handling Vulnerability (CVE-2026-49135)
slug: 2026-06-codexbar-tmp-file
description: CodexBar versions prior to 0.32.0 are vulnerable to insecure temporary file handling, allowing local attackers to access sensitive credentials or tamper with build artifacts due to predictable file paths in the release notarization workflow.
date: "2026-06-01T21:19:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - insecure-temp-file
  - local-privilege-escalation
products:
  - CodexBar < 0.32.0
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-49135
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49135
rules:
  - title: Detect CVE-2026-49135 Exploitation - Suspicious File Creation in Temporary Directories
    description: Detects CVE-2026-49135 exploitation - Creation of files in common temporary directories which may indicate an attempt to exploit insecure temporary file handling.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect CVE-2026-49135 Exploitation - Symbolic Link Creation in Temporary Directories
    description: Detects CVE-2026-49135 exploitation - Creation of symbolic links in temporary directories, potentially redirecting file writes to attacker-controlled locations.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CodexBar prior to version 0.32.0 is susceptible to an insecure temporary file handling vulnerability. This flaw enables local attackers to potentially access sensitive credentials or manipulate build artifacts by exploiting predictable file paths during the release notarization process. The vulnerability allows attackers with local access to the system to read the App Store Connect API key from a fixed path, pre-create files or symbolic links at predictable locations to redirect writes to attacker-controlled destinations, or tamper with notarization archives before submission. This could lead to unauthorized access, code injection, or supply chain compromise.

## Attack Chain

1.  Attacker gains local access to a system running a vulnerable version of CodexBar.
2.  The attacker identifies the fixed file path used by CodexBar to store the App Store Connect API key during the release notarization workflow.
3.  Attacker reads the App Store Connect API key from the predictable file path.
4.  Alternatively, the attacker identifies predictable locations used for temporary files during notarization.
5.  The attacker pre-creates files or symbolic links at these predictable locations, redirecting writes to attacker-controlled destinations.
6.  CodexBar writes data to the attacker-controlled locations, potentially overwriting or modifying critical system files.
7.  Attacker tampers with notarization archives before submission, injecting malicious code or build artifacts.
8.  The compromised notarization archive is submitted, potentially leading to the distribution of malicious software.

## Impact

Successful exploitation of this vulnerability allows local attackers to access sensitive App Store Connect API keys, potentially leading to unauthorized access to the developer's account. Furthermore, attackers can tamper with notarization archives, injecting malicious code or build artifacts into the software release, leading to supply chain compromise. The number of potential victims depends on the adoption rate of CodexBar in software development environments.

## Recommendation

*   Upgrade CodexBar to version 0.32.0 or later to remediate the insecure temporary file handling vulnerability (CVE-2026-49135).
*   Monitor file creation events in sensitive directories for unexpected file creations or symbolic links using the provided Sigma rule.
*   Implement strict file permission policies to limit access to sensitive files and directories, mitigating the risk of unauthorized access.
