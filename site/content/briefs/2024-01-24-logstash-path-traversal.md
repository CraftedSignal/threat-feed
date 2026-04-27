---
title: Logstash Arbitrary File Write via Path Traversal (CVE-2026-33466)
slug: 2024-01-24-logstash-path-traversal
description: CVE-2026-33466 describes a vulnerability in Logstash where improper validation of file paths within compressed archives allows arbitrary file writes, potentially leading to remote code execution.
date: "2026-04-08T18:26:00Z"
severities:
  - high
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

CVE-2026-33466 exposes a critical vulnerability in Logstash, stemming from improper validation of file paths within compressed archives. This flaw, classified as CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), can be exploited by an attacker to achieve arbitrary file writes on the host system. The attack vector involves serving a specially crafted archive to Logstash, typically through a compromised or attacker-controlled update endpoint. This malicious archive contains…
