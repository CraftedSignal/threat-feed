---
title: OpenClaw Arbitrary File Read Vulnerability via QQBot Media Tags (CVE-2026-43533)
slug: 2026-05-openclaw-file-read
description: OpenClaw before 2026.4.10 is vulnerable to an arbitrary file read via specially crafted QQBot media tags, allowing attackers to disclose local files through outbound media handling.
date: "2026-05-05T12:16:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary file read
  - path traversal
  - CVE-2026-43533
vendors:
  - openclaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-43533
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43533
  - https://github.com/openclaw/openclaw/commit/604777e4414cc3b2ff8861f18f4fb04374c702c6
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-66r7-m7xm-v49h
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-local-file-read-via-qqbot-media-tags
rules:
  - title: Detect Suspicious Path Traversal in OpenClaw QQBot Media Tags
    description: Detects potential path traversal attempts in OpenClaw QQBot media tags by looking for '../' sequences in the message content.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Requests for Sensitive Files via OpenClaw
    description: Detects outbound web requests from the OpenClaw server for sensitive files (e.g., /etc/passwd) indicating potential file read attempts.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.4.10 is susceptible to an arbitrary file read vulnerability (CVE-2026-43533) affecting the QQBot media tag functionality. This flaw enables an attacker to craft malicious reply text containing manipulated media tags that reference paths outside the intended media storage boundary, leading to the disclosure of arbitrary local files. Exploitation occurs through outbound media handling, potentially exposing sensitive information stored on the host system. This vulnerability allows unauthorized access to local files, which could include configuration files, user data, or other sensitive information.

## Attack Chain

1. The attacker identifies an OpenClaw instance running a version prior to 2026.4.10 with QQBot enabled.
2. The attacker crafts a malicious message containing a QQBot media tag referencing a file path outside the intended media storage directory (e.g., using "../" sequences for path traversal).
3. The attacker sends the malicious message to a user or bot connected to the vulnerable OpenClaw instance.
4. The OpenClaw instance parses the message and attempts to process the media tag.
5. Due to the vulnerability, the OpenClaw instance reads the file specified in the malicious media tag, regardless of its location on the filesystem.
6. The contents of the file are then included in the outbound media handling process, potentially being sent to another user or external service.
7. The attacker receives the file contents, achieving arbitrary file read on the vulnerable system.

## Impact

Successful exploitation of CVE-2026-43533 allows an attacker to read arbitrary files on the system running the vulnerable OpenClaw instance. This could lead to the disclosure of sensitive information, such as configuration files, credentials, or user data. The vulnerability affects all installations of OpenClaw prior to version 2026.4.10 that have QQBot enabled. The impact is significant because an attacker can potentially gain complete control over the affected system by gaining access to sensitive configuration or credential files.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.10 or later to patch CVE-2026-43533.
*   Implement input validation and sanitization on QQBot media tags to prevent path traversal attacks.
*   Deploy the Sigma rule `Detect Suspicious Path Traversal in OpenClaw QQBot Media Tags` to identify exploitation attempts in your environment.
