---
title: Relative Path Traversal Vulnerability in mcpo-simple-server
slug: 2026-04-mcpo-simple-server-traversal
description: A relative path traversal vulnerability exists in getsimpletool mcpo-simple-server <= 0.2.0, allowing remote attackers to delete arbitrary files via manipulation of the `detail` argument in the `delete_shared_prompt` function.
date: "2026-04-29T21:16:22Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve-2026-7404
vendors:
  - getsimpletool
products:
  - mcpo-simple-server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7404
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7404
rules:
  - title: Detect Mcpo-Simple-Server Path Traversal Attempt
    description: Detects potential path traversal attempts in mcpo-simple-server by monitoring for '..' sequences in the URI query.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Mcpo-Simple-Server Path Traversal Attempt - Encoded
    description: Detects potential path traversal attempts in mcpo-simple-server with URL encoded '..' sequences in the URI query.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A relative path traversal vulnerability, identified as CVE-2026-7404, has been discovered in getsimpletool mcpo-simple-server up to version 0.2.0. The vulnerability resides within the `delete_shared_prompt` function of the `src/mcpo_simple_server/services/prompt_manager/base_manager.py` file. By manipulating the `detail` argument, a remote attacker can traverse the file system and delete arbitrary files. The vulnerability is remotely exploitable, and proof-of-concept exploit code is publicly available. The maintainers of the getsimpletool project have been notified of this vulnerability but have not yet responded. This poses a significant risk to systems running mcpo-simple-server, as it could lead to unauthorized file deletion and potential system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable mcpo-simple-server instance running version 0.2.0 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the `delete_shared_prompt` function.
3.  The malicious request includes a manipulated `detail` argument containing relative path traversal sequences (e.g., `../`).
4.  The server-side application processes the request and passes the manipulated `detail` argument to the `delete_shared_prompt` function.
5.  The `delete_shared_prompt` function uses the attacker-controlled `detail` argument to construct a file path.
6.  Due to the path traversal sequences, the resulting file path points to a location outside the intended directory.
7.  The application attempts to delete the file at the attacker-specified location.
8.  If permissions allow, the file is successfully deleted, leading to potential data loss or system instability.

## Impact

Successful exploitation of this vulnerability allows an attacker to delete arbitrary files on the affected system. This can lead to data loss, application malfunction, or even complete system compromise, depending on the files targeted for deletion. Given the public availability of exploit code, systems running vulnerable versions of mcpo-simple-server are at immediate risk. The impact is especially severe if the targeted files are critical system files or application data.

## Recommendation

*   Upgrade mcpo-simple-server to a patched version that addresses CVE-2026-7404, if available from the vendor.
*   Deploy the Sigma rule `Detect Mcpo-Simple-Server Path Traversal Attempt` to identify exploitation attempts in web server logs.
*   Implement strict input validation and sanitization on the `detail` argument of the `delete_shared_prompt` function, if patching is not immediately feasible.
*   Monitor web server logs for suspicious activity, such as requests containing path traversal sequences.
*   Restrict file system permissions to limit the impact of successful path traversal attacks.
