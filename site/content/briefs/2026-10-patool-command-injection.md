---
title: OS Command Injection in patool via Malicious Filenames
slug: 2026-10-patool-command-injection
description: The patool library prior to version 4.0.6 contains an OS command injection vulnerability on Windows that allows arbitrary command execution via crafted archive filenames.
date: "2026-10-07T12:37:23Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - patool (< 4.0.6)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can supply crafted filenames... to execute commands with patool process privileges.
    confidence_band: high
cves:
  - id: CVE-2026-106057
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106057
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade patool to version 4.0.6 or later.
      owner: IT Operations
      addresses: CVE-2026-106057
      evidence: patool before 4.0.6 contains an OS command injection vulnerability.
---

The patool library, a portable archive file manager, is vulnerable to OS command injection in versions prior to 4.0.6 when running on Windows. The issue stems from the shell_quote_nt function, which fails to correctly sanitize or escape cmd.exe metacharacters and embedded double quotes in archive filenames. When the library processes a crafted filename containing these characters (e.g., 'report&calc.gz') within a context where shell=True is invoked, it inadvertently triggers the execution of arbitrary commands. This vulnerability affects any Windows-based application or service that utilizes patool to handle untrusted user-supplied archive files, potentially leading to unauthorized code execution with the permissions of the application process.

## Impact

Successful exploitation allows for arbitrary code execution on the host machine with the privileges of the user running the patool-based application. This vulnerability poses a significant risk in environments where users can upload or provide archive files for automated processing, such as web applications or file-transfer services.

## Recommendation

Upgrade the patool library to version 4.0.6 or later immediately to resolve the shell_quote_nt escaping issue.

## Rules

title: "Detect Suspicious Command Execution via patool"
description: "Detects potential command injection exploitation where cmd.exe metacharacters are passed to a sub-process spawned by a python application process likely using patool."
logsource:
 category: process_creation
 product: windows
detection:
 selection:
 CommandLine|contains:
 - "&"
 - "|"
 - "&&"
 - "||"
 - "^"
 filter:
 Image|endswith:
 - "C:\\Windows\\System32\\cmd.exe"
 - "C:\\Windows\\SysWOW64\\cmd.exe"
 condition: selection and filter
level: high
tags:
 - attack.execution
 - attack.t1059.003
falsepositives:
 - "Legitimate administrative scripts using command chaining"
 - "System maintenance tasks"
tests:
 positive:
 - name: "Cmd.exe execution with shell metacharacters in command line"
 data:
 - Image: "C:\\Windows\\System32\\cmd.exe"
 CommandLine: "cmd.exe /c extract file&calc.exe"
 negative:
 - name: "Standard process creation"
 data:
 - Image: "C:\\Windows\\System32\\cmd.exe"
 CommandLine: "cmd.exe /c echo hello"
handoff:
 detection_confidence: "medium"
 required_telemetry:
 - log_source: "Sysmon process_creation"
 event_or_channel: "Event ID 1"
 required_fields:
 - "Image"
 - "CommandLine"
 availability: "available"
 notes: "Monitor cmd.exe spawns for suspicious command line arguments."
 validation:
 status: "needs_environment_validation"
 known_evasions:
 - "Using alternative shells or direct API calls not involving cmd.exe."
 limitations:
 - "High potential for noise in administrative environments."
 tuning:
 - source: "Administrator scripts"
 guidance: "Exclude known administrative service accounts or deployment script paths."
