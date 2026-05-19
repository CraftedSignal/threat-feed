---
title: HAXcms createSite SSRF Enables Arbitrary File Read
slug: 2026-05-haxcms-ssrf
description: HAXcms is vulnerable to Server-Side Request Forgery (SSRF) via the createSite endpoint, allowing an authenticated user to supply arbitrary URLs or local file paths, which are fetched server-side without validation and written to a web-accessible directory, enabling arbitrary file read, internal network access, and cloud credential exposure; this vulnerability is tracked as CVE-2026-46393.
date: "2026-05-19T14:44:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - haxcms
  - cve-2026-46393
  - vulnerability
vendors:
  - HAXTheWeb
products:
  - HAXcms (<= 25.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-q862-gcgq-5m6g
  - CVE-2026-46393
iocs:
  - type: url
    value: http://attacker.com
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
  url: 1
rules:
  - title: Detect HAXcms createSite SSRF Attempt
    description: Detects attempts to exploit the HAXcms createSite SSRF vulnerability (CVE-2026-46393) by identifying POST requests to /createSite with suspicious URLs or file paths in the build.files parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect HAXcms Arbitrary File Access via SSRF
    description: Detects access attempts to files within the HAXcms sites directory after potential SSRF exploitation (CVE-2026-46393).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

HAXcms (v11.0.6) is vulnerable to Server-Side Request Forgery (SSRF) via the `createSite` endpoint due to insufficient validation of the `build.files` parameter. An authenticated user can supply arbitrary URLs or local file paths, which are then fetched server-side using `file_get_contents()` without validation. This allows for reading arbitrary files, accessing internal network services, and potentially exposing cloud credentials through metadata endpoints. This vulnerability was disclosed in GHSA-q862-gcgq-5m6g and is tracked as CVE-2026-46393. Exploitation requires an authenticated session, but default credentials are often present on fresh installs, lowering the barrier to entry.

## Attack Chain

1. Attacker authenticates to the HAXcms application using credentials (default `admin/admin` may work on fresh installs).
2. The attacker obtains a valid JWT and CSRF token from the authenticated session.
3. The attacker crafts a POST request to the `/createSite` endpoint with a JSON payload.
4. The payload includes a `build.files` parameter containing a filename (e.g., `poc.txt`) as the key and a `tmp_name` value set to the target URL or file path (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/` or `/etc/passwd`).
5. The HAXcms server processes the `build.files` parameter, extracting the `tmp_name` value without validation.
6. The server uses `file_get_contents()` to fetch the content from the URL or file path specified in `tmp_name`.
7. The fetched content is saved to the `sites/<sitename>/files/<filename>` directory.
8. The attacker retrieves the content by sending a GET request to `sites/<sitename>/files/<filename>`, thus achieving arbitrary file read or access to internal resources.

## Impact

This SSRF vulnerability can be exploited by any authenticated user to access sensitive information. Successful exploitation allows attackers to read arbitrary files from the server's file system (e.g., `/etc/passwd`, application configuration files), access internal network services, and potentially expose cloud credentials through metadata endpoints like `http://169.254.169.254`. This could lead to complete compromise of the server and potentially the associated cloud environment. The affected package `npm/@haxtheweb/haxcms-nodejs` (vulnerable: <= 25.0.0) means that many instances of HAXcms may be affected.

## Recommendation

*   Apply available patches or updates to HAXcms to address CVE-2026-46393.
*   Monitor web server logs for POST requests to `/createSite` with suspicious URLs or file paths in the `build.files` parameter, using the Sigma rule `Detect HAXcms createSite SSRF Attempt`.
*   Inspect network connections originating from the HAXcms server for connections to internal IP addresses or cloud metadata endpoints like 169.254.169.254, as highlighted in the IOC section.
*   Implement strict input validation on the `build.files` parameter of the `/createSite` endpoint to prevent arbitrary URL and file path injection.
