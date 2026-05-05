---
title: exiftool-vendored Argument Injection Vulnerability
slug: 2024-01-03-exiftool-arg-injection
description: exiftool-vendored is vulnerable to argument injection (CVE-2026-43893) via newline characters in tag names, potentially allowing attackers to read or write files accessible to the ExifTool process by injecting arguments through caller-supplied strings.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - argument-injection
  - exiftool
  - cve-2026-43893
vendors:
  - npm
products:
  - exiftool-vendored (<= 35.18.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-cw26-7653-2rp5
  - https://exiftool.org/exiftool_pod.html#stay_open-FLAG
  - https://exiftool.org/TagNames/
  - https://cwe.mitre.org/data/definitions/88.html
rules:
  - title: Detect Argument Injection in ExifTool via Command Line
    description: Detects potential argument injection attempts in ExifTool by monitoring for newline characters in command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Argument Injection in ExifTool via Filename Parameter
    description: Detects potential argument injection attempts in ExifTool by monitoring for suspicious characters in filename parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `exiftool-vendored` npm package, versions 35.18.0 and earlier, contains an argument injection vulnerability (CVE-2026-43893) stemming from insufficient sanitization of tag names and filenames. The package starts ExifTool in `-stay_open True -@ -` mode, reading arguments from stdin.  Attackers can inject arbitrary ExifTool arguments by including newline characters in tag names, filenames, or the `imageHashType` option passed to affected APIs. This can lead to unauthorized file access or modification within the ExifTool process's permissions. Applications using `exiftool-vendored` and passing attacker-controlled strings to vulnerable APIs are susceptible. The vulnerability was patched in version 35.19.0.

## Attack Chain

1. An attacker crafts a malicious input string containing newline characters, targeting a tag name or filename parameter.
2. The attacker-controlled string is passed to a vulnerable `exiftool-vendored` API, such as `ExifTool#write`, `#read`, or `#deleteAllTags`.
3. The newline characters split the intended argument into multiple arguments when ExifTool processes the command.
4. The injected arguments could cause ExifTool to read arbitrary files accessible to the ExifTool process.
5. Alternatively, the injected arguments could cause ExifTool to write to attacker-controlled file paths accessible to the ExifTool process.
6. Sensitive information is read from arbitrary files.
7. Files are modified or overwritten.
8. The attacker achieves unauthorized data access or system modification, depending on the application's usage of ExifTool.

## Impact

Successful exploitation of CVE-2026-43893 could allow attackers to read sensitive files or overwrite existing files on systems where `exiftool-vendored` is used.  The impact is dependent on the application's file system access permissions and its usage of the vulnerable `exiftool-vendored` APIs. There is no remote code execution reported.

## Recommendation

*   Upgrade to `exiftool-vendored` version 35.19.0 or later to remediate CVE-2026-43893.
*   Apply input validation to reject strings containing control characters (specifically newlines, carriage returns, and null bytes) before passing them to affected `exiftool-vendored` APIs. Reference the example `assertSafeForExifTool` function provided in the advisory.
*   Monitor application logs for unexpected file access or modification attempts originating from the ExifTool process.
*   Deploy the provided Sigma rules to detect exploitation attempts by monitoring process command lines for injected arguments.
