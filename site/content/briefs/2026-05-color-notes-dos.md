---
title: Color Notes 1.4 Denial-of-Service Vulnerability (CVE-2021-47969)
slug: 2026-05-color-notes-dos
description: Color Notes 1.4 is vulnerable to a denial-of-service attack (CVE-2021-47969) where pasting excessively long character strings into note fields can crash the application, achieved by generating and pasting a 350,000-character payload twice into a new note.
date: "2026-05-16T16:20:34Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - denial-of-service
  - application-crash
  - CVE-2021-47969
products:
  - Color Notes
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2021-47969
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47969
rules:
  - title: Detect Color Notes Crash via Process Terminate
    description: Detects CVE-2021-47969 exploitation — detects Color Notes process termination, which can indicate a crash due to a large payload
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Large Text File Creation
    description: Detects creation of extremely large text files, which could be used as a payload for CVE-2021-47969
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Color Notes 1.4 is susceptible to a denial-of-service vulnerability (CVE-2021-47969). This flaw allows an attacker to crash the application by exploiting its handling of extremely large text inputs. The attack involves crafting a payload consisting of a long, repeated character string, specifically a string of 350,000 characters. By pasting this oversized payload twice into a new note within the application, an attacker can overwhelm the application's resources, leading to a crash and rendering it temporarily unavailable. This vulnerability poses a threat to user productivity and data integrity.

## Attack Chain

1.  Attacker crafts a malicious payload consisting of a repeated character string of approximately 350,000 characters.
2.  Attacker opens the Color Notes 1.4 application.
3.  Attacker creates a new note within the application.
4.  Attacker pastes the crafted 350,000-character string into the new note field.
5.  Attacker pastes the same 350,000-character string again into the same note field.
6.  The application attempts to process the excessively large text input.
7.  The application's resources are exhausted due to the oversized payload.
8.  The application becomes unresponsive and crashes, resulting in a denial-of-service condition.

## Impact

The successful exploitation of this denial-of-service vulnerability results in the Color Notes 1.4 application becoming unresponsive and crashing. Users will be unable to access their notes and may experience data loss or corruption if the application does not properly save data before crashing. While the scope of this vulnerability is limited to a single application, it can still disrupt workflows and cause frustration for affected users. The number of victims is dependent on the usage of Color Notes 1.4.

## Recommendation

*   Monitor for process crashes of Color Notes 1.4 using the process_creation rule included in this brief.
*   Implement input validation and sanitization measures within Color Notes to limit the size of text inputs accepted by the application to prevent similar denial-of-service attacks.
*   Consider deploying the file_event rule included in this brief to monitor for the creation of excessively large text files which could be used as part of the attack.
