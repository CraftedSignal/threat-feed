---
title: SiYuan Note Taking Application Directory Traversal Vulnerability
slug: 2026-03-siyuan-traversal
description: SiYuan note taking application is vulnerable to a directory traversal via the /api/file/readDir endpoint, which does not require authentication, allowing an attacker to enumerate the directory structure and retrieve file names, potentially leading to arbitrary document reading.
date: "2026-03-26T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - directory-traversal
  - siyuan
  - cve-2026-33670
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://github.com/advisories/GHSA-xmw9-6r43-x9ww
rules:
  - title: SiYuan Directory Traversal Attempt
    description: Detects attempts to exploit the directory traversal vulnerability in SiYuan via the /api/file/readDir endpoint.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
  - title: SiYuan Directory Traversal - Suspicious Path in Request
    description: Detects potential directory traversal attempts in SiYuan by looking for '..' sequences in the path parameter of /api/file/readDir requests.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The SiYuan note-taking application is susceptible to a critical directory traversal vulnerability affecting versions up to 0.0.0-20260317012524-fe4523fff2c8. The vulnerability resides in the `/api/file/readDir` endpoint, which lacks authentication. This allows unauthenticated attackers to send POST requests to enumerate directories and retrieve file names within the application's data and configuration directories. Successful exploitation allows a malicious actor to gain sensitive information about the application's file structure, and could be chained with a file-reading vulnerability to achieve arbitrary document access. This poses a significant risk to confidentiality and data security.

## Attack Chain

1.  An attacker identifies a vulnerable SiYuan instance.
2.  The attacker sends an unauthenticated POST request to the `/api/file/readDir` endpoint.
3.  The POST request includes a `path` parameter specifying the directory to list, such as `data` or `conf`.
4.  The SiYuan application processes the request without authentication and returns a JSON response containing a list of files and directories within the specified path.
5.  The attacker parses the JSON response to identify interesting files and directories.
6.  The attacker repeats steps 2-5 to traverse deeper into the directory structure.
7.  The attacker identifies the location of sensitive documents or configuration files.
8.  The attacker leverages a separate file reading vulnerability (not detailed in this brief) to access and exfiltrate the identified documents or configuration files, gaining unauthorized access to sensitive information.

## Impact

Successful exploitation of this directory traversal vulnerability allows an attacker to enumerate the entire directory structure of a SiYuan notebook. This may expose sensitive information stored within the application's data and configuration files. When combined with a file reading vulnerability, attackers can access and exfiltrate arbitrary documents, potentially leading to data breaches and confidentiality compromise. The number of affected users is potentially large, given the popularity of the SiYuan note-taking application. Targeted sectors would include any organization or individual using SiYuan for storing sensitive information.

## Recommendation

*   Apply updates to SiYuan to versions greater than 0.0.0-20260317012524-fe4523fff2c8 that patch CVE-2026-33670.
*   Monitor web server logs for POST requests to the `/api/file/readDir` endpoint, as detailed in the rule below, and investigate unexpected activity.
*   Deploy the Sigma rule provided to detect exploitation attempts in web server logs, tuning it for your environment.
*   Block access from IP address `172.18.40.184` observed in the exploit PoC, if seen connecting to your SiYuan instances.
