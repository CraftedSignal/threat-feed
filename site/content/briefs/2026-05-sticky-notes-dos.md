---
title: Sticky Notes & Color Widgets 1.4.2 Denial of Service Vulnerability (CVE-2021-47972)
slug: 2026-05-sticky-notes-dos
description: Sticky Notes & Color Widgets 1.4.2 is vulnerable to denial of service via excessively long character strings (CVE-2021-47972), allowing attackers to crash the application.
date: "2026-05-16T16:21:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial of service
  - application crash
  - cve-2021-47972
products:
  - Sticky Notes & Color Widgets 1.4.2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2021-47972
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47972
  - https://www.exploit-db.com/exploits/49957
  - https://www.vulncheck.com/advisories/sticky-notes-color-widgets-denial-of-service
rules:
  - title: Detect CVE-2021-47972 Exploitation Attempt - Large String Input
    description: Detects CVE-2021-47972 exploitation attempt — unusually large string input into the Sticky Notes application, potentially leading to a denial of service.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2021-47972 Exploitation Attempt - Repeated String Pattern
    description: Detects CVE-2021-47972 exploitation attempt — repeated pattern in Sticky Notes input string, suggesting DoS attempt.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Sticky Notes & Color Widgets 1.4.2 is susceptible to a denial-of-service (DoS) vulnerability. This vulnerability, identified as CVE-2021-47972, allows a remote, unauthenticated attacker to crash the application. By crafting notes containing excessively long character strings, an attacker can exhaust the application's resources, leading to a crash and rendering the application unresponsive. The vulnerability was reported on May 16, 2026.

## Attack Chain

1.  Attacker opens the Sticky Notes & Color Widgets application.
2.  Attacker creates a new note within the application.
3.  Attacker pastes a large payload of repeated characters (an excessively long string) into the note's text field.
4.  The application attempts to allocate memory to store the overly large note content.
5.  Due to the excessive size of the string, the memory allocation fails or consumes excessive resources.
6.  The application becomes unresponsive as it struggles to process the oversized data.
7.  The application crashes due to resource exhaustion or a memory allocation error.
8.  The Sticky Notes & Color Widgets application is no longer available to the user until restarted.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition. The Sticky Notes & Color Widgets application becomes unusable, disrupting the user's workflow. While the vulnerability does not lead to data loss or compromise of the system, it can cause inconvenience and temporary loss of productivity. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high impact on availability.

## Recommendation

*   Monitor application logs for unusual memory allocation patterns, which could indicate exploitation attempts.
*   Implement input validation to limit the size of notes created within the application to mitigate CVE-2021-47972.
*   Deploy the Sigma rule to identify potential attempts to exploit the denial-of-service vulnerability.
*   Consider contacting the vendor for a patch or update addressing CVE-2021-47972.
