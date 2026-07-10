---
title: changedetection.io Authentication Bypass via Flask Decorator Misordering
slug: 2024-01-changedetectionio-auth-bypass
description: changedetection.io is vulnerable to authentication bypass due to incorrect decorator ordering in Flask routes, allowing unauthenticated access to backup functionalities and potentially leading to data exfiltration of sensitive information.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - data-exfiltration
  - flask
vendors:
  - changedetection.io
products:
  - changedetection.io
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
references:
  - https://github.com/advisories/GHSA-jmrh-xmgh-x9j4
iocs:
  - type: domain
    value: changedetection.io
ioc_counts:
  domain: 1
rules:
  - title: Detect changedetection.io Backup Download Without Authentication
    description: Detects attempted or successful download of a changedetection.io backup file without authentication based on HTTP status code 200 on affected route.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1020
    data_sources:
      - webserver
      - linux
  - title: Detect changedetection.io Backup Request Without Authentication
    description: Detects attempted backup creation without authentication based on HTTP status code 302 on affected route.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1020
    data_sources:
      - webserver
      - linux
rules_count: 2
---

changedetection.io versions 0.54.7 and earlier contain an authentication bypass vulnerability affecting 13 routes across 5 blueprint files. The vulnerability stems from the `@login_optionally_required` decorator being incorrectly placed before the `@blueprint.route()` decorator in Flask route definitions. This misconfiguration prevents the authentication wrapper from being applied to the affected routes, effectively disabling authentication checks. This allows unauthenticated users to access sensitive functionalities, like backups, which would normally require authentication. This issue is due to an inconsistency in the application of decorators, as other routes correctly implement the proper decorator order. Successful exploitation allows attackers to extract sensitive data such as watched URLs, notification webhook URLs including API tokens, and configuration data.

## Attack Chain

1. An unauthenticated attacker sends a request to `/backups/request-backup` to trigger a backup creation.
2. The server, without proper authentication, creates a new backup and redirects the user to `/backups/`.
3. The attacker then accesses `/backups/` to list all available backups. This route is also exposed.
4. The attacker parses the HTML response from `/backups/` to identify the filenames of the created backups, specifically looking for entries matching `changedetection-backup`.
5. The attacker sends a request to `/backups/download/<filename>` with the identified backup filename to download the backup. Again, no authentication is required.
6. The server delivers the requested ZIP archive containing sensitive application data.
7. The attacker extracts the downloaded backup and obtains sensitive information, including `url-watches.json`, `secret.txt` (Flask secret key), and other configuration files.
8. As a final step, the attacker can trigger the `/backups/remove-backups` endpoint which deletes all the backup files on the server.

## Impact

Successful exploitation of this vulnerability allows for complete data exfiltration of sensitive information stored within application backups. This includes monitored URLs, notification webhook URLs, API tokens (for services like Slack and Discord), and the Flask secret key. An attacker could use the exfiltrated Flask secret key to craft malicious sessions. The ability to download backups also allows for configuration injection, potentially leading to remote code execution. The application may also be susceptible to SSRF attacks via the proxy check endpoint if authentication is bypassed. This flaw can also lead to browser session hijacking by manipulating Playwright sessions.

## Recommendation

*   Apply the provided remediation by swapping the order of the decorators on the 13 affected routes, ensuring that `@blueprint.route()` is the outermost decorator (see Remediation section in the source).
*   Monitor web server logs for requests to the affected `/backups/` routes without valid authentication credentials (e.g., missing session cookies or tokens). Use category "webserver" and product "linux" or "windows" with appropriate filters to detect unauthenticated requests to `/backups/*`.
*   Deploy the provided Sigma rule to detect successful downloads from the affected route `/backups/download/<filename>`.
