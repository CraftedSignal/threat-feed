---
title: SecureDrop Client Code Execution via Gzip Extraction Vulnerability
slug: 2026-04-securedrop-gzip-vuln
description: A compromised SecureDrop server can achieve code execution on the SecureDrop client's virtual machine by exploiting improper filename validation during gzip archive extraction, allowing for the overwriting of critical files.
date: "2026-04-18T01:16:18Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - securedrop
  - gzip
  - code execution
  - vulnerability
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Malicious File
cves:
  - id: CVE-2026-35465
    cvss: 7.5
  - id: CVE-2025-24888
    cvss: 8.1
    epss: 0.0307
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35465
rules:
  - title: Detect SecureDrop Client File Overwrite Attempt
    description: Detects attempts to overwrite critical files within the SecureDrop Client installation directory, potentially indicating exploitation of CVE-2026-35465.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Process Accessing SecureDrop SQLite Database
    description: Detects processes other than the SecureDrop client accessing the SQLite database, which might indicate unauthorized access after a successful exploit.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

SecureDrop Client, a desktop application designed for secure communication between journalists and sources, is vulnerable to code execution (versions 0.17.4 and below). The vulnerability, identified as CVE-2026-35465, stems from improper filename validation during the extraction of gzip archives. A compromised SecureDrop Server can leverage this flaw to overwrite critical files, such as the SQLite database, on the Client's virtual machine (sd-app). While exploiting this vulnerability requires prior compromise of the hardened SecureDrop Server (accessible only via Tor), successful exploitation leads to significant impact on the confidentiality, integrity, and availability of sensitive source submissions. This issue is similar to CVE-2025-24888, but arises through a different code path. Version 0.17.5 addresses this vulnerability with a more robust fix within the replacement SecureDrop Inbox codebase.

## Attack Chain

1. Attacker compromises the SecureDrop Server, gaining control over its file handling processes.
2. Attacker crafts a malicious gzip archive containing filenames with absolute paths (e.g., `/opt/securedrop/client/db.sqlite`).
3. Attacker uploads this malicious gzip archive to the compromised SecureDrop Server.
4. The SecureDrop Client retrieves the malicious gzip archive from the SecureDrop Server via Tor.
5. The SecureDrop Client attempts to extract the contents of the gzip archive using a vulnerable extraction routine.
6. Due to improper filename validation, the extraction process overwrites critical files, such as the SQLite database, on the client's virtual machine (sd-app).
7. The attacker achieves code execution by manipulating the overwritten files to execute arbitrary code upon the next application startup or during normal operation.
8. The attacker gains unauthorized access to decrypted source submissions and can exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-35465 allows a compromised SecureDrop Server to execute arbitrary code on the SecureDrop Client's virtual machine. This leads to a complete breach of confidentiality, integrity, and availability of decrypted source submissions handled by the client. Journalists relying on SecureDrop could have their sources exposed, leading to severe repercussions for both journalists and their sources. The impact is limited to SecureDrop deployments running vulnerable versions (0.17.4 and below).

## Recommendation

*   Upgrade all SecureDrop Client installations to version 0.17.5 or later to remediate CVE-2026-35465.
*   Monitor SecureDrop Client systems for unusual file writes, especially to critical directories such as `/opt/securedrop/client/` using the provided Sigma rule.
*   Review and harden the SecureDrop Server's security configuration to prevent initial compromise, as exploitation requires prior access to the server.
