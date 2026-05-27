---
title: compliance-trestle Arbitrary File Write via Cache Path Traversal
slug: 2026-05-compliance-trestle-arbitrary-file-write
description: The compliance-trestle library is vulnerable to an arbitrary file write via cache path traversal due to improper sanitization of URL path components in the remote fetching cache mechanism, potentially leading to remote code execution.
date: "2026-05-27T22:58:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - compliance-trestle
  - arbitrary-file-write
  - path-traversal
  - rce
vendors:
  - IBM
products:
  - compliance-trestle
references:
  - https://github.com/advisories/GHSA-g3vg-vx23-3858
  - https://cwe.mitre.org/data/definitions/22.html
  - https://cwe.mitre.org/data/definitions/73.html
  - https://github.com/IBM/compliance-trestle
iocs:
  - type: domain
    value: evil.com
ioc_counts:
  domain: 1
rules:
  - title: Detect compliance-trestle Arbitrary File Write via Cache Path Traversal
    description: Detects attempts to exploit CVE-2026-45725 by identifying process execution involving compliance-trestle and file writes outside the intended cache directory.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    data_sources:
      - process_creation
      - linux
  - title: Detect compliance-trestle Cache Directory Access Violation
    description: Detects access to files or directories outside the designated cache directory by the compliance-trestle process, indicating a potential path traversal exploit related to CVE-2026-45725.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The compliance-trestle library, version 4.0.2 and earlier, contains a vulnerability in its remote fetching cache mechanism (HTTPSFetcher and SFTPFetcher) within the `trestle/core/remote/cache.py` file. This flaw allows for arbitrary file writes due to insufficient sanitization of path traversal sequences (`../`) in URLs. A malicious OSCAL profile referencing a URL containing path traversal elements can cause the HTTP response body to be written to an arbitrary location on the filesystem, outside of the intended cache directory. This vulnerability was reported on 2026-05-27 and can be exploited to achieve remote code execution.

## Attack Chain

1. An attacker crafts a malicious OSCAL profile containing an `imports` section with a URL to a controlled server (e.g., `https://evil.com/../../../../../../../tmp/trestle_pwned.json`).
2. The compliance-trestle library parses the malicious OSCAL profile and extracts the URL from the `imports` section.
3. The `HTTPSFetcher` or `SFTPFetcher` class within `cache.py` is instantiated to fetch the remote resource.
4. The library uses `urlparse` to parse the URL, but it does not sanitize the path component for path traversal sequences.
5. The library constructs a local cache path using the hostname and the unsanitized path component, resulting in a path outside the intended cache directory.
6. The library creates the necessary directories using `mkdir(parents=True, exist_ok=True)`, effectively creating the arbitrary path on the filesystem.
7. The library fetches the content from the attacker's server using `requests.get` or an SFTP client.
8. The fetched content, controlled by the attacker, is written to the arbitrary file path using `write_text`, leading to arbitrary file write and potentially remote code execution (e.g., by writing to cron job directories or SSH authorized keys).

## Impact

Successful exploitation of this vulnerability allows an attacker to write arbitrary files to the filesystem with the privileges of the user running the compliance-trestle application. This can lead to various impacts, including remote code execution via cron job injection, unauthorized SSH access via authorized keys injection, or configuration file overwrites. The number of victims and targeted sectors are currently unknown, but any system using a vulnerable version of compliance-trestle is susceptible.

## Recommendation

- Upgrade to a patched version of compliance-trestle that addresses the path traversal vulnerability.
- Apply the provided remediation steps to sanitize path components and implement boundary checks in `cache.py`.
- Monitor network traffic for requests to suspicious domains like `evil.com` referenced in the IOC table.
- Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect potential exploitation attempts.
