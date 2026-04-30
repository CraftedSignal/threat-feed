---
title: Rack::Static Information Disclosure Vulnerability (CVE-2026-34785)
slug: 2026-04-rack-static-disclosure
description: Rack versions prior to 2.2.23, 3.1.21, and 3.2.6 are vulnerable to information disclosure due to improper static file serving via a prefix matching issue in Rack::Static.
date: "2026-04-02T17:16:24Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - rack
  - information-disclosure
  - CVE-2026-34785
  - ruby
  - webserver
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-34785
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34785
rules:
  - title: Detect Suspicious Rack Static File Access
    description: Detects attempts to access potentially sensitive files via Rack::Static by checking for common sensitive file extensions within configured static directories.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Rack Static File Access - Backup Files
    description: Detects access to backup files within Rack static directories.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Rack, a modular Ruby web server interface, is susceptible to an information disclosure vulnerability in versions prior to 2.2.23, 3.1.21, and 3.2.6. The flaw resides in the Rack::Static middleware component, which uses a simple string prefix check to determine if a request should be served as a static file. When configured with URL prefixes, such as "/css", Rack::Static incorrectly matches any request path starting with "/css", potentially serving unintended files like "/css-config.env" or "/css-backup.sql". This allows unauthorized access to sensitive files located under the static root directory. This vulnerability, identified as CVE-2026-34785, can lead to the disclosure of configuration files, database backups, and other sensitive information. The vulnerability has been patched in Rack versions 2.2.23, 3.1.21, and 3.2.6.

## Attack Chain

1. An attacker identifies a Rack-based web application using a vulnerable version of Rack (prior to 2.2.23, 3.1.21, or 3.2.6).
2. The attacker identifies a static file directory configured in the Rack application, for example using a path prefix like "/css".
3. The attacker crafts a malicious request targeting a sensitive file within the static directory, such as "/css-config.env" or "/css-backup.sql", that shares the configured prefix but is not intended to be served publicly.
4. The Rack::Static middleware incorrectly matches the malicious request due to the simple string prefix check.
5. The web server serves the unintended file to the attacker.
6. The attacker gains access to sensitive information contained in the served file.
7. The attacker leverages the disclosed information to further compromise the application or infrastructure.

## Impact

Successful exploitation of this vulnerability (CVE-2026-34785) can lead to the disclosure of sensitive information, including configuration files, database backups, and other critical data. The impact severity is dependent on the nature of the exposed files. For example, exposure of database credentials could result in a full compromise of the application's data. Organizations using vulnerable Rack versions are susceptible to information breaches if they rely on Rack::Static to serve files.

## Recommendation

*   Upgrade Rack to version 2.2.23, 3.1.21, or 3.2.6 or later to patch CVE-2026-34785.
*   Review Rack::Static configurations to ensure appropriate restrictions are in place for serving static files.
*   Deploy the Sigma rule "Detect Suspicious Rack Static File Access" to identify attempts to access files with similar prefixes.
*   Monitor web server logs (category: webserver) for unusual requests with file extensions such as `.env`, `.sql`, `.bak` that fall under static directories (e.g., /css, /js, /img).
