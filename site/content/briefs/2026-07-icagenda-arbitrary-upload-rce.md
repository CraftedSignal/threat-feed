---
brief_id: brief-2026-07-icagenda-arbitrary-upload-rce
event_id: brief-2026-07-icagenda-arbitrary-upload-rce
revision: 2
activity_at: "2026-11-19T18:13:06Z"
revision_history:
  - revision: 2
    at: "2026-11-19T18:13:06Z"
    checksum: sha256:e8e0df856ad85737ec40f681db592ab9ec3f49f928fdeeb17270dc8e53cb3d61
    summary: exploited:true; KEV CVE-2025-32432
    changed_fields:
      - cves
      - exploitation_evidence
      - iocs
      - lastmod
      - priority_score
      - priority_signals
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: iCagenda Unrestricted File Upload Vulnerability Leading to RCE (CVE-2026-48939)
slug: 2026-07-icagenda-arbitrary-upload-rce
description: Attackers are actively exploiting CVE-2026-48939, an unrestricted file upload vulnerability in iCagenda, to upload malicious PHP code and achieve remote code execution on affected web servers.
date: "2026-07-10T17:16:18Z"
lastmod: "2026-11-19T18:12:21Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-03-20T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=D24236F7-331C-5472-8852-CB4854D642E5&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - rce
  - file-upload
  - cve
vendors:
  - Balbooa
  - Breeze Cache
  - Craft CMS
  - Craftcms
  - Gravity Forms
  - iCagenda
  - JCE
  - Joomla
  - JoomliC
  - MaxSite
  - MetInfo
  - Ninja Forms
  - Sneeit
  - WavePlayer
  - WordPress
  - WPBookit
products:
  - Balbooa Forms
  - Balbooa Forms <= 2.4.0
  - Breeze Cache
  - Craft CMS
  - Gravity Forms
  - iCagenda
  - iCagenda < 3.9.15
  - iCagenda < 4.0.8
  - Joomla
  - Joomla JCE
  - MaxSite CMS
  - MetInfo CMS
  - Ninja Forms
  - Sneeit Framework
  - WavePlayer
  - WordPress
  - WPBookit
product_versions:
  - product: Craft CMS
    range: < 3.9.15
  - product: Craft CMS
    range: < 4.14.15
  - product: Craft CMS
    range: < 5.6.17
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: iCagenda contains an unrestricted upload of file with dangerous type vulnerability that allows the upload of arbitrary files in the file attachment feature, ultimately resulting in PHP code upload and execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.006
    subtechnique_name: Python
    evidence: ultimately resulting in PHP code upload and execution.
    confidence_band: high
cves:
  - id: CVE-2025-7852
    cvss: 9.8
    epss: 0.01217
    kev_status: unknown
  - id: CVE-2025-32432
    cvss: 10
    epss: 0.99829
    kev: true
    kev_status: "true"
  - id: CVE-2026-0740
    cvss: 9.8
    epss: 0.54254
    kev_status: unknown
  - id: CVE-2026-3844
    cvss: 9.8
    epss: 0.36512
    kev_status: unknown
  - id: CVE-2025-12057
    cvss: 9.8
    epss: 0.00448
    kev_status: unknown
  - id: CVE-2026-48939
    kev_status: unknown
  - id: CVE-2026-56291
    kev_status: unknown
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-48939
  - https://www.icagenda.com/#download
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48939
  - https://www.cisa.gov/news-events/alerts/2026/07/10/cisa-adds-two-known-exploited-vulnerabilities-catalog
  - https://thehackernews.com/2026/07/icagenda-and-balbooa-forms-joomla-flaws.html
  - https://sploitus.com/exploit?id=D24236F7-331C-5472-8852-CB4854D642E5&utm_source=rss&utm_medium=rss
iocs:
  - type: other
    value: icagenda-batch/1.0
  - type: filepath
    value: images/icagenda/frontend/attachments/
  - type: filepath
    value: images/baforms/uploads
  - type: other
    value: suspicious administrator accounts
  - type: filepath
    value: '*.php'
  - type: url
    value: https://sploitus.com/exploit?id=D24236F7-331C-5472-8852-CB4854D642E5
  - type: url
    value: https://sensepost.com/blog/2025/investigating-an-in-the-wild-campaign-using-rce-in-craftcms/
ioc_counts:
  filepath: 3
  other: 2
  url: 2
rules:
  - title: Detects CVE-2026-48939 Exploitation - Unrestricted File Upload of PHP Files
    description: Detects CVE-2026-48939 exploitation by monitoring web server logs for HTTP POST requests to iCagenda upload paths that include dangerous file extensions like .php, indicating an attempt to upload a web shell.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.006
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-10T18:11:27Z"
    level: L2
    summary: added CVE-2026-56291
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/alerts/2026/07/10/cisa-adds-two-known-exploited-vulnerabilities-catalog
  - at: "2026-07-13T07:02:12Z"
    level: L2
    summary: poc_available; added CVE-2025-12057 +4
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/icagenda-and-balbooa-forms-joomla-flaws.html
  - at: "2026-07-21T18:04:09Z"
    level: L2
    summary: craft cms version < 5.6.17; OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=D24236F7-331C-5472-8852-CB4854D642E5&utm_source=rss&utm_medium=rss
  - at: "2026-11-19T18:12:21Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-32432
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

CVE-2026-48939, an unrestricted upload of file with dangerous type vulnerability in the iCagenda component for Joomla, is being actively exploited in the wild. This critical vulnerability allows remote, unauthenticated attackers to upload arbitrary files, including malicious PHP web shells, through the file attachment feature of the application. Upon successful upload, the attacker can execute the planted PHP code, leading to full remote code execution on the compromised web server. CISA has added CVE-2026-48939 to its Known Exploited Vulnerabilities Catalog, requiring federal agencies to apply mitigations by July 13, 2026. This vulnerability poses a significant risk as it can lead to complete system compromise, data exfiltration, or further network penetration.

## Attack Chain

1. An unauthenticated attacker identifies an internet-facing iCagenda instance vulnerable to CVE-2026-48939.
2. The attacker crafts an HTTP POST request targeting an iCagenda file attachment endpoint, such as `/index.php?option=com_icagenda&task=file.upload`.
3. The request includes a malicious file, typically a PHP web shell (e.g., `shell.php` or `image.jpg.php`), within the `$_FILES` parameter.
4. Due to the unrestricted file upload vulnerability, the iCagenda application processes and saves the malicious file to a publicly accessible directory on the web server without proper validation of its type or content.
5. The attacker then accesses the uploaded web shell via a direct HTTP GET request to its known or inferred path (e.g., `/images/icagenda/uploads/shell.php`).
6. Upon accessing the web shell, the embedded PHP code executes on the server, granting the attacker remote command execution capabilities.
7. The attacker leverages the web shell to conduct further activities such as establishing persistence, escalating privileges, exfiltrating data, or deploying additional malware like ransomware.

## Impact

Successful exploitation of CVE-2026-48939 grants attackers full remote code execution capabilities on the compromised web server. This leads to complete control over the web application, potential access to the underlying operating system, and sensitive data stored on the server or connected databases. The impact can range from website defacement and data theft to the deployment of ransomware or other destructive malware across the organization's network. As this vulnerability is on CISA's KEV catalog, it is actively exploited, posing an immediate and severe threat to organizations using iCagenda.

## Recommendation

* Immediately apply security updates or mitigations provided by iCagenda for CVE-2026-48939, as specified in the vendor instructions referenced by CISA.
* Deploy the provided Sigma rule to your SIEM to detect attempts at arbitrary file uploads with dangerous extensions to web server paths.
* Review web server access logs for any suspicious HTTP POST requests to upload endpoints followed by subsequent GET requests to newly created PHP files, as described in the attack chain.
* If mitigation is unavailable, follow CISA's BOD 26-04 guidance to discontinue use of the affected product or isolate it from internet exposure.
