---
title: Logstash Arbitrary File Write via Path Traversal (CVE-2026-33466)
slug: 2024-01-24-logstash-path-traversal
description: CVE-2026-33466 describes a vulnerability in Logstash where improper validation of file paths within compressed archives allows arbitrary file writes, potentially leading to remote code execution.
date: "2026-04-08T18:26:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - remote-code-execution
  - logstash
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-33466
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33466
rules:
  - title: Detect Logstash Path Traversal Archive Extraction
    description: Detects potential path traversal attempts during archive extraction by monitoring for suspicious file creation events with path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect Logstash Out-of-Directory File Creation
    description: Detects file creation events outside of the intended Logstash directories.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-33466 exposes a critical vulnerability in Logstash, stemming from improper validation of file paths within compressed archives. This flaw, classified as CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), can be exploited by an attacker to achieve arbitrary file writes on the host system. The attack vector involves serving a specially crafted archive to Logstash, typically through a compromised or attacker-controlled update endpoint. This malicious archive contains file paths designed to traverse directories, allowing the attacker to write files outside of the intended Logstash directories with the privileges of the Logstash process. If Logstash is configured with automatic pipeline reloading, this arbitrary file write can be leveraged to execute arbitrary code, effectively achieving remote code execution (RCE).

## Attack Chain

1.  Attacker identifies a Logstash instance with a vulnerable version of the archive extraction utility and a potential attack vector via update endpoints.
2.  Attacker crafts a malicious compressed archive containing files with relative path traversal sequences in their filenames (e.g., "../../path/to/malicious/file.conf").
3.  Attacker compromises or controls an update endpoint used by Logstash to retrieve updates, such as pipeline configurations or plugins.
4.  Logstash retrieves the malicious archive from the compromised update endpoint.
5.  Logstash extracts the contents of the archive using a vulnerable archive extraction utility.
6.  Due to insufficient path validation, the utility writes the files to arbitrary locations on the filesystem, overwriting existing files or creating new ones. A common target could be Logstash's configuration directory.
7.  If automatic pipeline reloading is enabled, Logstash detects the modified configuration file and reloads the pipeline.
8.  The malicious configuration file contains embedded code that executes arbitrary commands on the system with the privileges of the Logstash process, achieving remote code execution.

## Impact

Successful exploitation of CVE-2026-33466 can lead to complete compromise of the Logstash server. An attacker can gain arbitrary code execution, allowing them to install malware, steal sensitive data, or disrupt services. The CVSS v3.1 base score of 8.1 reflects the high potential for damage. While the number of potential victims and targeted sectors are unknown, any organization using a vulnerable Logstash instance is at risk.

## Recommendation

*   Apply the patch or upgrade to a version of Logstash that addresses CVE-2026-33466 as soon as it becomes available.
*   Implement strict input validation on any update endpoints used by Logstash to prevent the delivery of malicious archives.
*   Disable automatic pipeline reloading in Logstash if possible, or implement controls to verify the integrity of pipeline configurations before reloading.
*   Deploy the Sigma rule `Detect Logstash Path Traversal Archive Extraction` to detect potential exploitation attempts by monitoring for suspicious file creation events.
*   Monitor file creation events for files created outside of the intended Logstash directories using the `Detect Logstash Out-of-Directory File Creation` Sigma rule.
