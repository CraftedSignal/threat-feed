---
title: TA488 Exploits Zimbra Mailservers with Half-Click Vulnerability CVE-2025-66376
slug: 2026-07-ta488-zimbra-half-click
description: Russia-aligned threat actor TA488 (Void Blizzard, Laundry Bear) exploited CVE-2025-66376, a critical XSS vulnerability in Zimbra Collaboration Suite webmail, for at least five months in 2025 via crafted emails to gain persistent access, exfiltrate user credentials, 2FA codes, and bulk emails from Ukrainian government and US defense industrial base targets.
date: "2026-07-23T14:04:47Z"
lastmod: "2026-07-24T06:58:47Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - TA488
  - Void Blizzard
  - Laundry Bear
cpes:
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:*:*:*:*:*:*:*:*
  - cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
has_poc: true
tags:
  - espionage
  - xss
  - zimbra
  - apt
  - state-sponsored
  - half-click
  - cve-2025-66376
vendors:
  - Zimbra
  - Microsoft
  - Synacor
  - WinRAR
  - Notepad++
  - Kerio
  - SOGo
  - mDaemon
  - Roundcube
products:
  - Zimbra Collaboration Suite
  - Zimbra Collaboration Suite (<= 2025-11)
  - Microsoft Exchange
  - Zimbra Collaboration Suite (ZCS) < 10.1.13
  - WinRAR
  - Notepad++
  - Zimbra mail servers
  - Kerio Webmail
  - SOGo Webmail <= 5.12.8
  - mDaemon
  - Roundcube
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
    evidence: TA488 sent messages exploiting CVE-2025-66376 from both adversary-controlled Proton Mail accounts and previously compromised addresses, to target entities in the government and education sectors. The messages use generic lures and do not require the targeted user to click on a link or open an attachment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The XSS exploit is embedded directly in the HTML body of the message and fires as soon as the victim opens or previews it in the vulnerable Zimbra webmail client. No further user interaction is required.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Account Manipulation
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
    evidence: ZimReaper gathering auto-complete password information.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
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
cves:
  - id: CVE-2025-66376
    cvss: 7.2
    epss: 0.12009
  - id: CVE-2026-8496
    cvss: 6.1
    epss: 0.00283
  - id: CVE-2025-49113
    cvss: 9.9
    epss: 0.94741
references:
  - https://www.proofpoint.com/us/blog/threat-insight/ta488-targets-zimbra-mailservers-half-click-exploits
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a
  - https://www.darkreading.com/cyberattacks-data-breaches/russian-hackers-zimbra-zero-day-us-ukraine-targets
  - https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html
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
  - title: Detect ZimReaper DNS Exfiltration Activity
    description: Detects ZimReaper malware exfiltrating sensitive data (credentials, 2FA codes, Zimbra info) via DNS queries, characterized by specific keys (2fa, c, e, pa, pw, url) and Base32 encoded data in subdomains, as described in TA488 campaigns.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1048
      - T1071.004
    data_sources:
      - dns_query
      - windows
  - title: Detect ZimReaper Bulk Email Exfiltration via Webmail Export
    description: Detects ZimReaper malware using Zimbra Collaboration Suite's webmail export functionality to exfiltrate bulk emails in TGZ format via HTTP POST requests, indicating a compromised user session by TA488.
    platform: sigma
    severity: high
    tactics:
      - collection
      - exfiltration
    techniques:
      - T1041
      - T1114.002
    data_sources:
      - webserver
rules_count: 2
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
---

Proofpoint, in coordination with the NSA and FBI, has identified TA488 (also known as Void Blizzard or Laundry Bear), a Russia-aligned threat actor, exploiting a critical cross-site scripting (XSS) vulnerability, CVE-2025-66376, in Zimbra Collaboration Suite mailservers. This campaign, active for at least five months during 2025, leveraged a "half-click" exploit, meaning victims needed only to open or preview a specially crafted email for malicious JavaScript to execute. The attacks primarily targeted Ukrainian government entities, along with US government, high science, and defense industrial base organizations. After successful exploitation, TA488 established persistent access to compromised systems, stole credentials and two-factor authentication codes, and exfiltrated emails using a custom malware Proofpoint tracks as "ZimReaper." The actor's use of this stealthy method underscores a continued focus by Russian state-sponsored groups on exploiting webmail vulnerabilities to achieve espionage objectives.

## Attack Chain

1. **Initial Access & Exploitation (CVE-2025-66376):** TA488 sends specially crafted emails from adversary-controlled Proton Mail accounts or previously compromised addresses. These emails contain an embedded HTML/JavaScript payload that exploits CVE-2025-66376 by using tag-splitting techniques with fake CSS `@import` directives and HTML comments to bypass Zimbra's client-side HTML sanitizer.
2. **Client-Side JavaScript Execution:** When a victim opens or previews the malicious email in a vulnerable Zimbra webmail client, the sanitizer fails, allowing the browser to reconstruct and execute the embedded JavaScript (ZimReaper) within the context of the user's authenticated webmail session.
3. **Obfuscation & Persistence Check:** The initial JavaScript, after execution, checks for a script element with the ID `zmb_pl_v3_` to avoid re-execution and subsequently XOR decrypts a second, obfuscated JavaScript payload.
4. **Credential & System Information Collection:** The decrypted ZimReaper JavaScript pings the attacker's C2 server to log the successful exploit and then proceeds to steal the Cross-Site Request Forgery (CSRF) token, auto-complete passwords, two-factor authentication codes, and details about the Zimbra installation from the browser.
5. **Persistence Establishment:** ZimReaper utilizes Zimbra APIs, specifically `CreateAppSpecificPasswordRequest`, to generate a new app-specific password under the name "ZimbraWeb." This password provides TA488 with persistent access to the mailserver via IMAP, POP3, or SMTP, bypassing 2FA requirements.
6. **Data Exfiltration via DNS Queries:** The collected sensitive information, including 2FA scratch codes, Zimbra version, user email, the newly created app-specific password, auto-fill password, and the Zimbra server URL, is exfiltrated to the C2 server via DNS queries using a specific `key.Base32EncodedData.unique_identifier.domain` schema.
7. **Bulk Email Exfiltration via HTTP POST:** ZimReaper iterates through up to 90 days of the targeted user's emails. It then leverages Zimbra's built-in export functionality to exfiltrate these messages as a TGZ (compressed tarball) file through an HTTP POST request to the attacker's C2 infrastructure.

## Impact

The successful exploitation of CVE-2025-66376 by TA488 results in significant compromise of targeted organizations, particularly within government, high science, and the defense industrial base sectors. The primary impact is the unauthorized exfiltration of sensitive email communications, user credentials, and two-factor authentication codes, leading to a severe loss of confidentiality. Furthermore, the establishment of persistent access via app-specific passwords enables the threat actor to maintain long-term presence within the mail environment, potentially send further spear-phishing campaigns from compromised legitimate accounts, or continue manual data exfiltration. The targeting of Ukrainian government entities and US defense contractors indicates a clear espionage objective, posing a national security risk.

## Recommendation

* Patch CVE-2025-66376 on all Zimbra Collaboration Suite mailservers immediately to prevent exploitation.
* Deploy the Sigma rule "Detect ZimReaper DNS Exfiltration Activity" to your SIEM and monitor for suspicious DNS queries that match the described pattern (`key.Base32EncodedData.unique_identifier.domain`).
* Deploy the Sigma rule "Detect ZimReaper Bulk Email Exfiltration via Webmail Export" to your SIEM and monitor Zimbra webserver logs for HTTP POST requests to `/service/export` with `fmt=tgz`.
* Review Zimbra audit logs for the creation of new app-specific passwords, particularly those named "ZimbraWeb", which may indicate unauthorized persistence.
* Enhance email gateway security to detect and block emails containing complex, obfuscated HTML/JavaScript payloads, especially those targeting known Zimbra vulnerabilities.
