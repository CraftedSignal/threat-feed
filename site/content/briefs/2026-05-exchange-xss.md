---
title: CVE-2026-42897 Microsoft Exchange Server Cross-Site Scripting Vulnerability
slug: 2026-05-exchange-xss
description: CVE-2026-42897 is a cross-site scripting (XSS) vulnerability in Microsoft Exchange Server that allows an attacker to perform spoofing attacks by injecting malicious scripts into web pages.
date: "2026-05-14T17:03:19Z"
lastmod: "2026-08-05T09:12:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:microsoft:exchange_server:2016:-:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_1:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_10:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_11:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_12:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_13:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_14:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_15:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_16:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_17:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_18:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_19:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_2:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_20:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_21:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_22:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_23:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_3:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_4:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_5:*:*:*:*:*:*
has_poc: true
tags:
  - xss
  - spoofing
  - exchange
vendors:
  - Microsoft
  - Zimbra
products:
  - Exchange Server
  - Exchange Server 2016
  - Exchange Server 2019
  - Exchange Server Subscription Edition (SE)
  - Outlook Web Access
  - Microsoft Outlook Web Access (<= 2026-05)
  - Zimbra Collaboration Suite
  - Outlook Webmail
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationships
cves:
  - id: CVE-2026-42897
    cvss: 8.1
    epss: 0.70307
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42897
  - https://www.bleepingcomputer.com/news/microsoft/microsoft-warns-of-exchange-zero-day-flaw-exploited-in-attacks/
  - https://www.jpcert.or.jp/english/at/2026/at260017.html
  - https://therecord.media/russia-hackers-outlook-webmail-malware
iocs:
  - type: url
    value: https://msrc.microsoft.com/update-guide/en-US/releaseNote/2026-Jun
  - type: url
    value: https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-42897
  - type: url
    value: https://www.catalog.update.microsoft.com/
  - type: url
    value: https://support.microsoft.com/en-us/help/12373/windows-update-faq
  - type: url
    value: https://msrc.microsoft.com/update-guide/
  - type: email
    value: ew-info@jpcert.or.jp
  - type: url
    value: https://www.jpcert.or.jp/english/
  - type: url
    value: https://therecord.media/russia-hackers-outlook-webmail-malware
ioc_counts:
  email: 1
  url: 7
rules:
  - title: Detects CVE-2026-42897 Exploitation — Suspicious URI Containing Script Tags
    description: Detects CVE-2026-42897 exploitation — HTTP requests to Exchange Server with suspicious script tags in the URI indicating potential XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1189
      - T1553.002
    data_sources:
      - webserver
  - title: Detects CVE-2026-42897 Exploitation — Suspicious POST data Containing Script Tags
    description: Detects CVE-2026-42897 exploitation — HTTP POST requests to Exchange Server with suspicious script tags in the POST data, indicating potential XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1189
      - T1553.002
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-05-14T18:19:08Z"
    level: L2
    summary: added CVE-2026-42897
    sources:
      - nvd
  - at: "2026-05-15T09:43:21Z"
    level: L2
    summary: poc_available
    sources:
      - bleepingcomputer
  - at: "2026-06-14T08:46:39Z"
    level: L1
    summary: OS windows
    sources:
      - jpcert
  - at: "2026-07-29T15:03:22Z"
    level: L1
    summary: new product
    sources:
      - therecord
    source_urls:
      - https://therecord.media/russia-hackers-outlook-webmail-malware
  - at: "2026-08-05T09:12:18Z"
    level: L1
    summary: new IOCs
    sources:
      - risky-biz
    source_urls:
      - https://therecord.media/russia-hackers-outlook-webmail-malware
---

CVE-2026-42897 is a cross-site scripting (XSS) vulnerability affecting Microsoft Exchange Server. This vulnerability stems from improper neutralization of input during web page generation. An attacker can exploit this flaw to inject malicious scripts into web pages served by the Exchange Server, potentially leading to spoofing attacks against users. Successful exploitation could allow an attacker to impersonate legitimate users, steal sensitive information, or perform unauthorized actions on behalf of a user. This vulnerability requires prompt attention from security teams to prevent potential damage and maintain the integrity of Exchange Server environments.

## Attack Chain

1. Attacker identifies a vulnerable endpoint within Microsoft Exchange Server susceptible to XSS.
2. Attacker crafts a malicious script designed to perform a spoofing attack.
3. Attacker injects the malicious script into a web page served by the Exchange Server, potentially via a crafted URL or form input.
4. A legitimate user accesses the compromised web page.
5. The user's browser executes the injected script.
6. The script modifies the content of the web page to spoof a trusted interface or request user credentials.
7. The user, believing the spoofed content is legitimate, interacts with the malicious script, potentially providing sensitive information.
8. The attacker captures the user's credentials or other sensitive data.

## Impact

Successful exploitation of CVE-2026-42897 can result in unauthorized access to sensitive information, impersonation of legitimate users, and potential compromise of the Exchange Server environment. The spoofing attacks can mislead users into divulging credentials or performing actions that benefit the attacker. Given the widespread use of Microsoft Exchange Server, a successful attack could affect numerous organizations and individuals, leading to significant data breaches and financial losses.

## Recommendation

*   Deploy the Sigma rule provided below to detect potential exploitation attempts of CVE-2026-42897 by monitoring for suspicious script injections in HTTP requests to Exchange Server.
*   Ensure Microsoft Exchange Server is updated with the latest security patches to address CVE-2026-42897.
*   Implement input validation and output encoding mechanisms to prevent XSS vulnerabilities in web applications.
