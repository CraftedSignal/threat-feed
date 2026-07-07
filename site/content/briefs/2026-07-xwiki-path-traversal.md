---
title: XWiki Platform Old Core Path Traversal via /skin/ Endpoint (CVE-2026-34151)
slug: 2026-07-xwiki-path-traversal
description: An attacker can exploit CVE-2026-34151, a path traversal vulnerability in XWiki Platform Old Core through the `/skin/` action endpoint when hosted on Jetty 12+. This allows unauthenticated users to craft URLs to access and download arbitrary files on the server, such as `/etc/passwd` or sensitive XWiki configuration files (e.g., `xwiki.cfg`), potentially leading to information disclosure and further system compromise.
date: "2026-07-07T13:15:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-vulnerability
  - xwiki
  - jetty
  - cve
  - information-disclosure
  - platform:network
vendors:
  - XWiki
  - Eclipse Foundation
products:
  - XWiki Platform Old Core (< 17.10.5)
  - XWiki Platform Old Core (>= 18.0.0-rc-1, < 18.2.0)
  - Jetty (12+)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit a path traversal vulnerability in XWiki Platform Old Core through the `/skin/` action endpoint when hosted on Jetty 12+.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: allows downloading the content of the /etc/passwd file, provided Jetty is allowed to read it
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: users should not be allowed to access Hibernate or XWiki configuration files is `http://[host]/xwiki/bin/skin/..%252f/..%252fWEB-INF/xwiki.cfg`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qj4x-9g63-25g6
  - https://jira.xwiki.org/browse/XWIKI-24075
  - https://jira.xwiki.org/browse/XCOMMONS-3594
iocs:
  - type: url
    value: http://[host]/xwiki/bin/skin/..%252f/..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd
  - type: url
    value: http://[host]/xwiki/bin/skin/..%252f/..%252fWEB-INF/xwiki.cfg
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-34151 Exploitation — XWiki Path Traversal
    description: Detects CVE-2026-34151 exploitation — HTTP GET requests to XWiki's /skin/ endpoint containing double URL-encoded path traversal sequences ('..%252f') which could lead to arbitrary file disclosure.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1005
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-34151 identifies a critical path traversal vulnerability affecting XWiki Platform Old Core versions prior to 17.10.5 and between 18.0.0-rc-1 and 18.2.0, specifically when deployed on Jetty 12+ application servers. This flaw allows unauthenticated attackers to construct specially crafted URLs that, when processed by the vulnerable XWiki instance, can bypass directory restrictions. This enables access to any file on the underlying operating system that the Jetty process has permissions to read, including sensitive system files like `/etc/passwd` or application-specific configuration files such as `xwiki.cfg` and Hibernate settings. The vulnerability poses a significant information disclosure risk, as it could expose critical system and application data, potentially leading to further reconnaissance, credential harvesting, or escalation of privileges by a threat actor.

## Attack Chain

1.  **Initial Access:** An unauthenticated attacker sends an HTTP GET request to the vulnerable XWiki application's `/xwiki/bin/skin/` endpoint.
2.  **Payload Crafting:** The attacker embeds double URL-encoded path traversal sequences (`..%252f`) within the URL path following the `/skin/` action.
3.  **Targeting Sensitive Files:** The crafted URL aims to traverse directories to reach sensitive files, such as `http://[host]/xwiki/bin/skin/..%252f/..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd` for system files or `http://[host]/xwiki/bin/skin/..%252f/..%252fWEB-INF/xwiki.cfg` for application configuration files.
4.  **Application Processing:** The XWiki application, running on Jetty 12+, processes the request to the `/skin/` endpoint.
5.  **Path Traversal Execution:** Due to the vulnerability, Jetty 12+ misinterprets the encoded path traversal sequences, allowing the application to access resources outside its intended web application directory.
6.  **File Retrieval:** The web server retrieves the content of the targeted file (e.g., `/etc/passwd`, `xwiki.cfg`) from the file system.
7.  **Data Disclosure:** The server responds to the attacker with the contents of the sensitive file, revealing potentially critical system or application information.
8.  **Impact:** This leads to information disclosure, which can be used for reconnaissance, identifying user accounts, understanding application architecture, or finding credentials for subsequent attacks.

## Impact

Successful exploitation of CVE-2026-34151 can lead to severe information disclosure. Attackers can access any file on the server that the Jetty instance has read permissions for, including operating system files like `/etc/passwd`, revealing local user accounts and system configuration. More critically, it allows access to sensitive XWiki and Hibernate configuration files (e.g., `xwiki.cfg`), which often contain database connection strings, API keys, and other proprietary application settings. This information can be leveraged for further attacks, such as database compromise, privilege escalation, or lateral movement within the network. There are no reported victim counts, but any organization running affected XWiki versions on Jetty 12+ is at risk across all sectors.

## Recommendation

*   **Patch CVE-2026-34151:** Immediately upgrade XWiki Platform Old Core to version 17.10.5 or 18.2.0 or later to remediate CVE-2026-34151.
*   **Deploy Detection Rule:** Deploy the provided Sigma rule "Detects CVE-2026-34151 Exploitation — XWiki Path Traversal" to your SIEM solution to identify attempts to exploit this vulnerability.
*   **Monitor Webserver Logs:** Configure web server logging for HTTP requests to capture full URIs and query strings, specifically for unusual access patterns to the `/xwiki/bin/skin/` endpoint containing `..%252f` or similar encoded path traversal sequences.
*   **Implement Workarounds (if patching is not immediate):** As a temporary measure, consider migrating XWiki to an application server other than Jetty 12+, such as Tomcat or an older version of Jetty (< 12), as these are not impacted by this specific vulnerability.
