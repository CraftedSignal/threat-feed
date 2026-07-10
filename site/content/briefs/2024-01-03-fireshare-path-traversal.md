---
title: Fireshare 1.5.1 Authenticated Path Traversal Vulnerability (CVE-2026-33645)
slug: 2024-01-03-fireshare-path-traversal
description: Fireshare version 1.5.1 is vulnerable to an authenticated path traversal, allowing attackers to write arbitrary files outside the intended upload directory due to insufficient sanitization of the `checkSum` field in the chunked upload endpoint.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - fireshare
vendors:
  - Fireshare
products:
  - Fireshare
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unprotected Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unprotected Credentials
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33645
rules:
  - title: Fireshare Suspicious File Upload Path
    description: Detects potential path traversal attempts in Fireshare chunked file uploads by identifying suspicious sequences in the URI query.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
  - title: Fireshare File Creation in /tmp with Suspicious Name
    description: Detects file creation events in /tmp with names containing suspicious sequences, potentially indicating path traversal exploitation in Fireshare.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1552
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Fireshare, a self-hosted media and link sharing platform, is susceptible to a critical path traversal vulnerability in version 1.5.1. This flaw, identified as CVE-2026-33645, resides within the chunked upload endpoint. By manipulating the `checkSum` multipart field, an authenticated attacker can write arbitrary files to locations outside of the designated upload directory. The vulnerability stems from the direct use of the `checkSum` field in filesystem path construction without proper sanitization or containment checks. Successful exploitation allows writing to any path writable by the Fireshare process (e.g., `/tmp` in containerized deployments), enabling potential compromise and follow-on attacks. Upgrading to version 1.5.2 resolves this vulnerability.

## Attack Chain

1.  Attacker authenticates to the Fireshare application.
2.  Attacker initiates a chunked file upload to the vulnerable endpoint.
3.  Attacker crafts a malicious HTTP POST request with a `checkSum` multipart field containing a path traversal payload (e.g., `../../../tmp/evil.sh`).
4.  The Fireshare server processes the request and constructs the file path using the unsanitized `checkSum` value.
5.  The server writes the uploaded chunk to the attacker-specified location (e.g., `/tmp/evil.sh`).
6.  Attacker uploads the complete malicious file through subsequent chunked upload requests.
7.  Attacker executes the uploaded file through other means, such as a web shell or command injection vulnerability (out of scope).
8.  Attacker achieves arbitrary code execution on the server, potentially leading to privilege escalation or data exfiltration.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-33645) in Fireshare 1.5.1 allows attackers to write arbitrary files to sensitive locations. This could lead to complete compromise of the Fireshare instance, including the ability to execute arbitrary code. Depending on the deployment environment (e.g., containerized), this may also lead to host compromise. Without specific figures, the potential number of affected installations depends on the adoption rate of Fireshare 1.5.1 before patching.

## Recommendation

*   Upgrade Fireshare installations to version 1.5.2 or later to remediate CVE-2026-33645.
*   Implement the provided Sigma rule `Fireshare Suspicious File Upload Path` to detect attempts to exploit this vulnerability via web server logs.
*   Monitor web server logs for POST requests to the chunked upload endpoint with suspicious path traversal sequences in the `cs-uri-query` field using the same Sigma rule.
