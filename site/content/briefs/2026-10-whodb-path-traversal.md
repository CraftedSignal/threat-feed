---
title: WhoDB Path Traversal Vulnerability (CVE-2026-112005)
slug: 2026-10-whodb-path-traversal
description: WhoDB versions prior to 0.135.0 are vulnerable to path traversal via DuckDB filesystem functions in the query editor, enabling remote unauthenticated file read and write access.
date: "2026-10-18T12:21:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:whodb:whodb:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - web-vulnerability
  - whodb
  - cve-2026-112005
vendors:
  - WhoDB
products:
  - WhoDB (< 0.135.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this to read, write, or overwrite arbitrary files on the host
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can log in to a DuckDB file without credentials and use read_text, read_blob, COPY ... TO or ATTACH to steal session.key
    confidence_band: high
cves:
  - id: CVE-2026-112005
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112005
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all WhoDB instances to 0.135.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source identifies version 0.135.0 as the remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to WhoDB query interface endpoints
      owner: Network Security
      addresses: CVE-2026-112005
      evidence: Mitigation for unauthenticated exploitation
---

WhoDB versions 0.104.0 through 0.134.x contain a critical path traversal vulnerability, tracked as CVE-2026-112005. The flaw originates from the insecure exposure of DuckDB filesystem functions within the application's query editor interface. An unauthenticated attacker can exploit this by executing specific DuckDB SQL functions to bypass intended directory restrictions. By leveraging functions such as read_text, read_blob, COPY, or ATTACH, an attacker can read arbitrary sensitive files on the host filesystem, including session keys and database credentials. Furthermore, the vulnerability allows for file overwriting, potentially facilitating code execution or persistence by modifying configuration files or binary assets. This vulnerability is particularly concerning because the query interface does not require authentication to execute these file-system operations, granting direct access to the underlying host OS from the application layer.

## Attack Chain

1. Attacker identifies a network-exposed instance of WhoDB (version < 0.135.0).
2. Attacker accesses the web-based query editor interface without providing authentication credentials.
3. Attacker crafts a SQL query using DuckDB's filesystem functions, specifically targeting sensitive files like session.key or configuration files.
4. Attacker executes the malicious query via the POST endpoint associated with the query editor.
5. The application backend processes the request and invokes the underlying DuckDB filesystem driver with attacker-controlled path arguments.
6. The application returns the contents of the requested file or performs the requested write/overwrite operation on the host filesystem.
7. Attacker exfiltrates the contents of the read file (e.g., credentials) via the web interface response or achieves persistence by overwriting a target file.

## Impact

Successful exploitation allows remote attackers to perform arbitrary file reads and writes on the host running the WhoDB service. This can lead to the complete compromise of database credentials, leakage of session keys, and potential remote code execution through the overwriting of executable or configuration files. Organizations running public-facing WhoDB instances are at immediate risk of full server takeover.

## Recommendation

* Patch immediately by upgrading all WhoDB instances to version 0.135.0 or later.
* If an upgrade is not immediately feasible, restrict access to the WhoDB query editor interface using network-level controls (e.g., VPN or firewall IP allowlisting) to ensure only authorized personnel can access the application.
* Audit web server logs for HTTP POST requests to the query editor endpoint that contain suspicious SQL keywords such as 'read_text', 'read_blob', 'COPY', or 'ATTACH' in the request body.
