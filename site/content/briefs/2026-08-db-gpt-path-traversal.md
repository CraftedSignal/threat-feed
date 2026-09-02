---
title: Unauthenticated Path Traversal in DB-GPT
slug: 2026-08-db-gpt-path-traversal
description: DB-GPT version 0.8.1 is vulnerable to an unauthenticated path traversal attack allowing remote code execution via a crafted user_id HTTP header.
date: "2026-08-11T21:49:50Z"
lastmod: "2026-09-02T16:44:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:eosphoros_ai:db_gpt:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BOREAS37-CVE-2026-73034-POC&utm_source=rss&utm_medium=rss
tags:
  - web-application-vulnerability
  - path-traversal
  - rce
vendors:
  - Eosphoros AI
products:
  - DB-GPT (v0.8.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers can write attacker-controlled content to locations such as Python startup hooks... resulting in remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-73034
    cvss: 9.8
    epss: 0.05122
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73034
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BOREAS37-CVE-2026-73034-POC&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-73034 Exploitation - Path Traversal in user_id Header
    description: Detects exploitation of CVE-2026-73034 where an attacker injects directory traversal sequences into the user_id HTTP header during a file upload
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1505.002
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-09-02T16:44:24Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BOREAS37-CVE-2026-73034-POC&utm_source=rss&utm_medium=rss
---

DB-GPT version 0.8.1 contains a critical path traversal vulnerability (CVE-2026-73034) that allows unauthenticated remote attackers to write arbitrary files to the underlying server filesystem. The vulnerability exists within the application's file-upload endpoint, which improperly sanitizes the 'user_id' HTTP header. By injecting directory traversal sequences (such as ../) into this header, an attacker can escape the designated upload directory. This flaw is particularly severe as it allows an attacker to overwrite sensitive system files or application configuration, such as Python startup hooks, agent scripts, or task scheduling files, to achieve remote code execution. Given the CVSS score of 9.8, immediate patching or restricting access to the file-upload endpoint is necessary for all deployments of DB-GPT v0.8.1.

## Attack Chain

1. Attacker identifies a target running DB-GPT v0.8.1 with public access to the file-upload endpoint.
2. Attacker crafts a multipart HTTP POST request directed at the file-upload endpoint.
3. Attacker injects path traversal sequences (e.g., ../../../etc/cron.d/malicious) into the 'user_id' HTTP header.
4. The application processes the header, failing to validate the traversal characters, and resolves the target file path outside the intended upload directory.
5. The application writes the attacker-supplied payload to the traversal-targeted location on the server filesystem.
6. Attacker triggers the execution of the newly placed file (e.g., waiting for a cron job to run or a service restart).
7. The server executes the attacker-controlled code, establishing persistence or performing further system compromise.

## Impact

Successful exploitation allows for full remote code execution on the host server. This can lead to total system compromise, data exfiltration, or the deployment of further malicious tools. All organizations running DB-GPT v0.8.1 are affected, and the vulnerability is trivially exploitable by unauthenticated remote actors.

## Recommendation

- Upgrade DB-GPT to the latest version immediately to patch CVE-2026-73034.
- Until patching is possible, implement an ingress-level WAF rule to block HTTP requests containing path traversal sequences (e.g., "../") within the 'user_id' header.
- Audit server file integrity to check for unauthorized files written in sensitive system or application directories following this attack vector.
- Deploy the Sigma rule below to detect attempts to exploit the traversal vulnerability in web server logs.
