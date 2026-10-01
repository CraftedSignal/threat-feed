---
title: ReDoS Vulnerability in basic-ftp Directory Listing Parser
slug: 2026-10-basic-ftp-redos
description: A ReDoS vulnerability in the basic-ftp library allows a malicious FTP server to trigger quadratic-time CPU consumption during directory listing, causing a client-side denial of service.
date: "2026-10-01T20:23:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:basic-ftp_project:basic-ftp:*:*:*:*:*:node.js:*:*
products:
  - basic-ftp (<= 6.2.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The server whose directory a client lists controls that listing, so it can return one line that pins the Node.js event loop for as long as it likes.
    confidence_band: high
cves:
  - id: CVE-2026-102990
    epss: 0.00507
references:
  - https://github.com/advisories/GHSA-c475-qrg2-pj4r
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102990
action_plan:
  priority: elevated
  owners:
    - Development
    - AppSec
  mitigation_plan:
    - priority: immediate
      action: Upgrade basic-ftp to 6.2.1 or later
      owner: Development
      addresses: CVE-2026-102990
      evidence: CVE-2026-102990
---

The `basic-ftp` Node.js library contains a high-severity regular expression denial of service (ReDoS) vulnerability, tracked as CVE-2026-102990. The vulnerability resides within the `parseListUnix.js` module, specifically in the `RE_LINE` regex used to parse Unix-style directory listings. The regex pattern utilizes two adjacent capture groups that are prone to excessive backtracking when provided with non-matching input strings that mimic a valid directory listing prefix but lack the subsequent mandatory numeric size and date fields.

An attacker controlling an FTP server can serve a crafted directory listing line to an `basic-ftp` client. When the client executes `Client.list()`, the regex engine attempts to resolve the ambiguous token structure, resulting in quadratic-time (O(n²)) CPU complexity relative to the length of the malicious string. Because Node.js is single-threaded, this operation blocks the event loop entirely, rendering the client unresponsive for extended periods. Given the default `maxListingBytes` of 40 MB, a single malicious line can effectively hang the client process for minutes.

## Impact

The vulnerability results in a total client-side denial of service by freezing the Node.js event loop. This affects any application utilizing `basic-ftp` to connect to untrusted or compromised FTP servers. Depending on the scale of the malicious input provided, the process can remain unresponsive for extended periods, potentially disrupting mission-critical services or automated processes that rely on the FTP client.

## Recommendation

Prioritized actions for teams using the `basic-ftp` library:

- Update the `basic-ftp` package to a version patched against CVE-2026-102990.
- Audit all code paths using `Client.list()` to ensure that connections are restricted to trusted FTP servers only.
- Implement request timeouts at the application level to force-close connections that exceed expected latency thresholds, serving as a secondary mitigation against hanging event loops.
