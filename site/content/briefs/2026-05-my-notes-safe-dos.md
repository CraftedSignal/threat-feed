---
title: My Notes Safe 5.3 Denial-of-Service Vulnerability (CVE-2021-47971)
slug: 2026-05-my-notes-safe-dos
description: My Notes Safe 5.3 is vulnerable to a denial-of-service attack (CVE-2021-47971) where an attacker can crash the application by pasting excessively long character strings into note fields.
date: "2026-05-16T16:21:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - denial-of-service
  - cve-2021-47971
products:
  - My Notes Safe
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2021-47971
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47971
  - https://www.exploit-db.com/exploits/49954
  - https://www.vulncheck.com/advisories/my-notes-safe-denial-of-service-via-buffer-overflow
rules:
  - title: Detect CVE-2021-47971 Exploitation Attempt - My Notes Safe Crash
    description: Detects CVE-2021-47971 exploitation — monitors for application crashes associated with MyNotesSafe.exe, indicating a potential denial-of-service attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
      - dos
    techniques:
      - T1498
    data_sources:
      - application
      - windows
  - title: Detect Large Pasted Data to My Notes Safe
    description: Detects suspicious process that pastes a very large string to My Notes Safe
    platform: sigma
    severity: low
    tactics:
      - availability
      - dos
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

My Notes Safe 5.3 is susceptible to a denial-of-service (DoS) vulnerability. Discovered and reported by VulnCheck, CVE-2021-47971 allows a remote attacker to crash the application by exploiting a buffer overflow. The vulnerability occurs when the application attempts to process an excessively long string of characters pasted into a note field. Publicly available exploits demonstrate the generation of a 350,000 character payload, which when pasted twice into a new note, reliably triggers the application crash. This vulnerability poses a risk to users of My Notes Safe 5.3, potentially leading to data unavailability and disruption of service.

## Attack Chain

1. The attacker generates a large string of repeated characters, approximately 350,000 characters long.
2. The attacker opens the My Notes Safe 5.3 application.
3. The attacker creates a new note within the application.
4. The attacker pastes the generated string into a note field.
5. The attacker pastes the same generated string into the same note field a second time, doubling the length of the input string.
6. The application attempts to allocate memory for and process this excessively large input string.
7. Due to insufficient bounds checking, the application attempts to allocate an excessive amount of memory, leading to a buffer overflow.
8. The buffer overflow triggers a crash of the My Notes Safe 5.3 application, resulting in a denial of service.

## Impact

Successful exploitation of CVE-2021-47971 results in a denial-of-service condition, causing the My Notes Safe 5.3 application to crash. This can lead to temporary or prolonged unavailability of the application and potential loss of unsaved data. The vulnerability could be exploited by malicious actors to disrupt the service for legitimate users, potentially impacting productivity and data access. While the vulnerability does not lead to data exfiltration or remote code execution, the disruption of service can still be significant. The number of potential victims depends on the number of users of My Notes Safe 5.3.

## Recommendation

*   Monitor process crashes for `MyNotesSafe.exe` to detect potential exploitation attempts. Deploy the provided Sigma rule targeting process crashes (Logsource: Application, Event ID 1000) to identify anomalous application terminations.
*   Implement input validation and sanitization within My Notes Safe to prevent the processing of excessively long strings.
*   Upgrade to a patched version of My Notes Safe that addresses the buffer overflow vulnerability. Contact the vendor for patch availability.
*   Monitor network traffic for unusually large data transfers to the My Notes Safe application, which could indicate an attempt to exploit this vulnerability (Logsource: network_connection).
