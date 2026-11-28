---
brief_id: brief-2026-07-ta488-zimbra-half-click
event_id: brief-2026-07-ta488-zimbra-half-click
revision: 2
activity_at: "2026-11-28T11:38:08Z"
revision_history:
  - revision: 2
    at: "2026-11-28T11:38:08Z"
    checksum: sha256:e015cec1f0f2b3653a4cfde627cd47ba3fc04532a45e916c3b234bdd69c3ed92
    summary: exploited:true; KEV CVE-2025-49113
    changed_fields:
      - affected_products
      - content
      - cpes
      - cves
      - exploitation_evidence
      - iocs
      - lastmod
      - poc_references
      - priority_score
      - priority_signals
      - references
      - rules
      - source_assessment
      - summary
      - title
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AC8999-CVE-2025-49113&utm_source=rss&utm_medium=rss
title: 'Roundcube Webmail: Remote code execution via PHP object deserialization (CVE-2025-49113)'
slug: 2026-07-ta488-zimbra-half-click
description: Roundcube Webmail versions prior to 1.5.10 and 1.6.11 contain a deserialization vulnerability in upload.php that enables remote code execution by authenticated users.
date: "2026-07-23T14:04:47Z"
lastmod: "2026-11-28T11:37:41Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - TA488
  - Void Blizzard
  - Laundry Bear
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-11-28T11:37:34Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "1"
  rating: C1
  likelihood: likely
cpes:
  - cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AC8999-CVE-2025-49113&utm_source=rss&utm_medium=rss
tags:
  - espionage
  - xss
  - zimbra
  - apt
  - state-sponsored
  - half-click
  - cve-2025-66376
vendors:
  - Kerio
  - mDaemon
  - Microsoft
  - Notepad++
  - Roundcube
  - SOGo
  - Synacor
  - WinRAR
  - Zimbra
products:
  - Kerio Webmail
  - mDaemon
  - Microsoft Exchange
  - Notepad++
  - Roundcube
  - SOGo Webmail <= 5.12.8
  - Webmail
  - WinRAR
  - Zimbra Collaboration Suite
  - Zimbra Collaboration Suite (ZCS) < 10.1.13
  - Zimbra mail servers
product_versions:
  - product: Webmail
    range: < 1.5.10
  - product: Webmail
    range: '>= 1.6.0, < 1.6.11'
  - product: Zimbra Collaboration Suite
    range: <= 2025-11
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: TA488 (Void Blizzard, Laundry Bear) was exploiting a previously unknown vulnerability against Zimbra mailservers for at least five months during 2025, until the issue was patched with CVE-2025-66376.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.001
    subtechnique_name: Spearphishing Attachment
    evidence: TA488 sent messages exploiting CVE-2025-66376 from both adversary-controlled Proton Mail accounts and previously compromised addresses, to target entities in the government and education sectors. The messages use generic lures and do not require the targeted user to click on a link or open an attachment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.007
    subtechnique_name: JavaScript
    evidence: The XSS exploit is embedded directly in the HTML body of the message and fires as soon as the victim opens or previews it in the vulnerable Zimbra webmail client. No further user interaction is required.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    subtechnique_id: T1136.001
    subtechnique_name: Local Account
    evidence: ZimReaper also uses CreateAppSpecificPasswordRequest to set up an app-specific password under the name “ZimbraWeb” for persistent access to the mailserver.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: The JavaScript pings the C&C server to log that the exploit was successful, then steals the Cross-Site Request Forgery (CSRF) token and the auto-complete password of the logged-in user from the browser.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: ZimReaper gathering auto-complete password information.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
    subtechnique_id: T1114.002
    subtechnique_name: Remote Email Collection
    evidence: Finally, the JavaScript iterates over the last 90 days’ worth of emails accessible to the targeted user, and then uses Zimbra’s export functionality to exfiltrate those messages via an HTTP POST request in a TGZ file to the previously mentioned C&C.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: This material is exfiltrated alongside the victim’s email address, and information about the Zimbra installation, via DNS queries to the adversary C&C.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Zimbra’s export functionality to exfiltrate those messages via an HTTP POST request in a TGZ file to the previously mentioned C&C.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.
cves:
  - id: CVE-2025-66376
    cvss: 7.2
    epss: 0.12009
    kev_status: unknown
  - id: CVE-2026-8496
    cvss: 6.1
    epss: 0.00283
    kev_status: unknown
  - id: CVE-2025-49113
    cvss: 9.9
    epss: 0.94741
    kev: true
    kev_status: "true"
references:
  - https://www.proofpoint.com/us/blog/threat-insight/ta488-targets-zimbra-mailservers-half-click-exploits
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a
  - https://www.darkreading.com/cyberattacks-data-breaches/russian-hackers-zimbra-zero-day-us-ukraine-targets
  - https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html
  - https://cveawg.mitre.org/api/cve/CVE-2025-49113
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AC8999-CVE-2025-49113
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AC8999-CVE-2025-49113&utm_source=rss&utm_medium=rss
iocs:
  - type: domain
    value: EasySend.co
  - type: filename
    value: NppExport.dll
  - type: filename
    value: updater.rar
  - type: filename
    value: Evernote.zip
  - type: filename
    value: RemoteLibUpdater.exe
  - type: filename
    value: InitTest.dll
  - type: filename
    value: winrar.exe
ioc_counts:
  domain: 1
  filename: 6
rules:
  - title: Detect CVE-2025-49113 exploitation attempts
    description: Detects incoming HTTP requests to the upload.php endpoint containing potential serialized PHP object patterns in the _from parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-23T15:16:34Z"
    level: L2
    summary: zimbra collaboration suite version <= 2025-11
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a
  - at: "2026-07-23T21:34:50Z"
    level: L2
    summary: poc_available
    sources:
      - dark-reading
    source_urls:
      - https://www.darkreading.com/cyberattacks-data-breaches/russian-hackers-zimbra-zero-day-us-ukraine-targets
  - at: "2026-07-24T06:58:47Z"
    level: L2
    summary: added CVE-2025-49113 +1; OS windows
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html
  - at: "2026-11-28T11:37:41Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-49113
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AC8999-CVE-2025-49113&utm_source=rss&utm_medium=rss
---

## Overview
Roundcube Webmail versions before 1.5.10 and 1.6.x before 1.6.11 allow remote code execution by authenticated users. The vulnerability occurs because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

## Attack Chain
An authenticated user can pass a crafted value to the _from parameter in a URL targeting the program/actions/settings/upload.php endpoint to trigger PHP Object Deserialization, leading to arbitrary code execution.

## Impact
Successful exploitation results in remote code execution, with a CVSS base score of 9.9 (Critical).

## Recommendation
Upgrade to version 1.5.10 or later for the 1.5.x branch, or 1.6.11 or later for the 1.6.x branch.
