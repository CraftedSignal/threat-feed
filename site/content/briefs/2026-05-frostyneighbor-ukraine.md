---
title: FrostyNeighbor Targets Ukraine with Updated PicassoLoader Chain
slug: 2026-05-frostyneighbor-ukraine
description: The FrostyNeighbor threat actor is targeting Ukrainian governmental organizations with spearphishing emails containing malicious PDFs that deliver a JavaScript dropper (PicassoLoader) and ultimately a Cobalt Strike beacon.
date: "2026-05-15T07:00:16Z"
lastmod: "2026-07-23T14:07:56Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - FrostyNeighbor
cpes:
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:*:*:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:-:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p1:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p10:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p11:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p12:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p13:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p14:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p15:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p16:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p17:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p18:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p19:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p2:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p20:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p21:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p22:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p23:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p24:*:*:*:*:*:*
  - cpe:2.3:a:synacor:zimbra_collaboration_suite:9.0.0:p24.1:*:*:*:*:*:*
  - cpe:2.3:a:mdaemon:email_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ruoyi:ruoyi:*:*:*:*:*:*:*:*
has_poc: true
tags:
  - frostyneighbor
  - cyberespionage
  - cobaltstrike
  - picassoloader
  - ukraine
vendors:
  - Microsoft
  - Cloudflare
  - Roundcube
  - WinRAR
  - Alinto
  - Zimbra
  - MDaemon Technologies
  - Kerio Technologies
products:
  - Cobalt Strike
  - WinRAR
  - Roundcube
  - Webmail (< 1.5.10)
  - Webmail (< 1.6.11)
  - SOGo webmail (< 5.12.8)
  - Zimbra webmail
  - MDaemon Email Server
  - Kerio Webmail
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: 'Phishing: Spearphishing Attachment'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.005
    technique_name: 'Command and Scripting Interpreter: Visual Basic Script'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053.005
    technique_name: 'Scheduled Task/Job: Scheduled Task'
cves:
  - id: CVE-2025-27915
    cvss: 5.4
    epss: 0.04344
  - id: CVE-2025-3929
    cvss: 6.1
    epss: 0.00517
  - id: CVE-2023-43770
    cvss: 6.1
    epss: 0.58483
  - id: CVE-2026-8496
    cvss: 6.1
    epss: 0.00283
  - id: CVE-2024-42900
    cvss: 6.1
    epss: 0.00341
references:
  - https://www.welivesecurity.com/en/eset-research/frostyneighbor-fresh-mischief-digital-shenanigans/
  - https://cyber.gc.ca/en/alerts-advisories/vulnerability-impacting-roundcube-webmail-cve-2025-49113
  - https://www.proofpoint.com/us/blog/threat-insight/ta458-roundpress-exploits
iocs:
  - type: domain
    value: book-happy.needbinding[.]icu
  - type: url
    value: https://book-happy.needbinding[.]icu/wp-content/uploads/2023/10/1GreenAM.jpg
  - type: domain
    value: nama-belakang.nebao[.]icu
  - type: domain
    value: share-ya.space
  - type: domain
    value: xwe.us
  - type: domain
    value: hgmydr.wiki
  - type: domain
    value: xsza.net
  - type: domain
    value: zxzaq.com
  - type: domain
    value: upgybj.store
  - type: hash_sha256
    value: 625e4c166c7a1d5a1becf56b27d4f76a2f95935cbd8d556c30a493263d10dbf8
  - type: hash_sha256
    value: a0c80cab70d6672b01710a70f93311fc1c1db2fbbf9cd6daa543c34b87e3444a
  - type: hash_sha256
    value: fb8ec4dbed14c0a91361abd82ebe9fb083615c3dbb15348f57317af7cc41dd34
  - type: hash_sha256
    value: 3a449148a0e3cac604fb93210dd7d91ccf48e06ed9aae064bc53a419a84ce9ba
  - type: hash_sha256
    value: 8b5a4dc237a4c89042176bc89864a4c357dcdd14fa544fe6496ccb6c31cd5b7f
  - type: hash_sha256
    value: 6b2c02bf82087a3ca5fb7ef8046554ff29ce85d52202bdcfae2b2653aede139a
  - type: hash_sha256
    value: e27d1bf82249002a66395c89dbda6ec5d8df012a84b79d36fffbbf7808d28878
ioc_counts:
  domain: 8
  hash_sha256: 7
  url: 1
rules:
  - title: Detect JavaScript Dropping Another JavaScript File
    description: Detects JavaScript files dropping other JavaScript files, a common technique used by downloaders like PicassoLoader.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Cobalt Strike Beacon Process rundll32.exe
    description: Detects rundll32.exe executing from unusual locations, a common persistence method used by Cobalt Strike beacons.  This rule can be noisy and requires tuning in most environments.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-07-10T19:17:06Z"
    level: L2
    summary: poc_available; added CVE-2024-42009 +1
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/vulnerability-impacting-roundcube-webmail-cve-2025-49113
  - at: "2026-07-23T14:07:56Z"
    level: L2
    summary: added CVE-2023-43770 +4
    sources:
      - proofpoint
    source_urls:
      - https://www.proofpoint.com/us/blog/threat-insight/ta458-roundpress-exploits
---

ESET researchers have identified new activity from FrostyNeighbor (aka Ghostwriter, UNC1151, UAC-0057, TA445, PUSHCHA, Storm-0257) targeting governmental organizations in Ukraine starting in March 2026. FrostyNeighbor, believed to be aligned with Belarus' interests, has been active since at least 2016, primarily targeting countries neighboring Belarus. The group employs spearphishing, disinformation campaigns, and credential harvesting to compromise various entities. This recent campaign utilizes malicious PDFs delivered via spearphishing emails, exploiting server-side validation to deliver a malicious payload only to victims with Ukrainian IP addresses. The group continually updates its toolset and compromise chains to evade detection, with a focus on Ukraine, Poland, and Lithuania. The attack culminates in the deployment of a Cobalt Strike beacon for persistent access and control.

## Attack Chain

1. A spearphishing email delivers a malicious PDF file (e.g., 53_7.03.2026_R.pdf) impersonating Ukrtelecom, a Ukrainian telecommunications company.
2. If the victim's IP address is from Ukraine, the server delivers a RAR archive (e.g., 53_7.03.2026_R.rar) containing a JavaScript dropper (53_7.03.2026_R.js). Otherwise, a benign PDF is served.
3. The JavaScript dropper (53_7.03.2026_R.js) executes and drops a decoy PDF file to the victim, simultaneously executing a second-stage JavaScript downloader (PicassoLoader) named Update.js, which is embedded in base64 within the first-stage script.
4. The PicassoLoader script (Update.js) downloads a scheduled task template (config.xml) from a C&C server (book-happy.needbinding[.]icu) disguised as a JPG image (1GreenAM.jpg), but the server responds with text-based content, advertising an XML attachment.
5. The script creates a scheduled task to achieve persistence. The scheduled task is configured to execute PicassoLoader (Update.js) periodically.
6. The PicassoLoader script fingerprints the victim's computer, sending data to a C&C server using a URL like https://book-happy.needbinding[.]icu/employment/documents-and-resources.
7. Based on the fingerprint, the C&C server may deliver a Cobalt Strike beacon.
8. The Cobalt Strike beacon establishes persistence by copying rundll32.exe, writing a DLL to disk, and creating a registry entry to execute the copied rundll32.exe with the DLL.

## Impact

FrostyNeighbor's campaigns primarily target governmental, military, and key sectors in Eastern Europe, with a focus on Ukraine, Poland, and Lithuania. A successful compromise allows the attacker to gain persistent access to the victim's systems, enabling them to conduct cyberespionage activities, including data theft, surveillance, and potential disruption of critical infrastructure. While Ukrainian targeting focuses on military, defense, and governmental entities, victimology in Poland and Lithuania includes sectors like industrial and manufacturing, healthcare and pharmaceuticals, logistics, and governmental organizations.

## Recommendation

*   Monitor network traffic for connections to the C&C server domains listed in the IOC table, specifically `book-happy.needbinding[.]icu` and `nama-belakang.nebao[.]icu` to identify potential Cobalt Strike beacon activity.
*   Implement the provided Sigma rule to detect the execution of JavaScript files dropping other JavaScript files, indicative of PicassoLoader activity.
*   Inspect scheduled tasks for suspicious configurations that execute JavaScript files from the %AppData% directory to identify potentially compromised systems.
*   Block the malicious URLs listed in the IOC table at the network level, particularly `https://book-happy.needbinding[.]icu/wp-content/uploads/2023/10/1GreenAM.jpg`, to prevent the download of malicious scheduled task templates.
