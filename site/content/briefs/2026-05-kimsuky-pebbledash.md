---
title: Kimsuky Targets Organizations with Evolving PebbleDash-Based Tools
slug: 2026-05-kimsuky-pebbledash
description: Kimsuky, a North Korean APT group, is actively targeting organizations, primarily in South Korea, with evolving tactics and tools, leveraging spear-phishing emails and messenger contacts to deploy malware such as PebbleDash and AppleSeed for establishing backdoors and stealing information.
date: "2026-05-14T11:07:51Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Kimsuky
  - Black Banshee
  - Velvet Chollima
  - Emerald Sleet
  - Thallium
tags:
  - kimsuky
  - apt
  - spear-phishing
  - malware
  - pebbledash
  - appleseed
vendors:
  - Microsoft
  - GitHub
  - Cloudflare
products:
  - VSCode
  - Cloudflare Quick Tunnels
  - GitHub authentication
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/
  - https://www.cisa.gov/news-events/analysis-reports/ar20-133c
  - https://securelist.com/the-kimsuky-operation-a-north-korean-apt/57915/
  - https://www.ncsc.go.kr:4018/main/cop/bbs/selectBoardArticle.do?bbsId=SecurityAdvice_main&nttId=146934&pageIndex=1&searchCnd2=
  - https://www.genians.co.kr/en/blog/threat_intelligence/triple-combo
iocs:
  - type: hash_md5
    value: 995a0a49ae4b244928b3f67e2bfd7a6e
  - type: hash_md5
    value: 52f1ff082e981cbdfd1f045c6021c63f
  - type: hash_md5
    value: 65fc9f06de5603e2c1af9b4f288bb22c
  - type: hash_md5
    value: 8e15c4d4f71bdd9dbc48cd2cabc87806
  - type: hash_md5
    value: 8983ffa6da23e0b99ccc58c17b9788c7
ioc_counts:
  hash_md5: 5
rules:
  - title: Detect Suspicious Regsvr32/Rundll32 Execution from Unusual Locations
    description: Detects regsvr32.exe or rundll32.exe executing from suspicious locations like %temp% or C:\ProgramData, often used by malware droppers.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect JSE Dropper with Certutil and Powershell
    description: Detects JSE droppers using certutil to decode and powershell to execute payloads.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1105
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Kimsuky, also known as APT43, Ruby Sleet, Black Banshee, Sparkling Pisces, Velvet Chollima, and Springtail, is a prolific Korean-speaking threat actor that has been active since at least 2013. Kaspersky researchers have observed tactical shifts in the group's recent campaigns, including the use of new malware variants based on the PebbleDash platform and connections to the AppleSeed malware cluster. Kimsuky has been leveraging legitimate tools, such as VSCode Tunneling and Cloudflare Quick Tunnels, as well as the open-source DWAgent remote monitoring and management tool. These activities primarily target South Korean entities in both the public and private sectors, with PebbleDash attacks also observed in Brazil and Germany. The group uses spear-phishing emails and messenger contacts to deliver malicious attachments.

## Attack Chain

1.  Kimsuky initiates the attack by sending spear-phishing emails or contacting targets via messengers.
2.  The initial contact leads to the delivery of a malicious attachment disguised as a document, such as a compressed file.
3.  The attachments contain droppers in formats like .JSE, .EXE, .PIF, or .SCR, with filenames designed to entice the recipient to open them.
4.  JSE droppers decode Base64-encoded blobs, including a benign lure file and malicious code, storing them in locations like C:\ProgramData with random filenames.
5.  The benign lure file is opened to deceive the user, while the malicious payload uses `powershell.exe -windowstyle hidden certutil -decode [src path] [dst path]` for further decoding.
6.  The final payload is executed via command-line instructions, such as `regsvr32.exe /s [file path]` or `rundll32.exe [file path] [export function]`.
7.  Reger Dropper (.SCR) and Pidoc Dropper (.PIF) decrypt their payloads using XOR operations before deploying files in directories like %temp% or C:\ProgramData.
8.  Post-exploitation, Kimsuky uses legitimate tools like Visual Studio Code (VSCode) and DWAgent for remote access and control, ultimately aiming to establish backdoors and steal information from the compromised systems.

## Impact

Kimsuky primarily targets South Korean entities, including both public and private sectors. The PebbleDash cluster has also been observed targeting the medical, military, and defense industries worldwide, with compromises of Brazilian and South Korean defense organizations, as well as a German defense firm. A successful attack leads to the establishment of backdoors, data theft, and potential disruption of critical services. In 2024, the South Korean government released a security advisory regarding the AppleSeed cluster, demonstrating the significant impact of these attacks.

## Recommendation

*   Monitor process creation events for the execution of `regsvr32.exe` or `rundll32.exe` from unusual locations like `%temp%` or `C:\ProgramData` (see Attack Chain step 6) to detect potential malware execution. Deploy the Sigma rule "Detect Suspicious Regsvr32/Rundll32 Execution from Unusual Locations" to your SIEM and tune for your environment.
*   Implement detections for JSE droppers decoding and executing payloads via `powershell.exe` and `certutil.exe`. Deploy the Sigma rule "Detect JSE Dropper with Certutil and Powershell" to your SIEM and tune for your environment.
*   Monitor for the execution of legitimate tools such as VSCode or DWAgent from unexpected locations or with unusual command-line arguments, indicating potential post-exploitation activity (see Attack Chain step 8).
*   Scan your environment for the MD5 hashes listed in the IOC table to identify potentially compromised systems.
*   Educate users about the risks of opening attachments from untrusted sources and verify the legitimacy of files before opening them, especially those disguised as documents or application installers (see Attack Chain step 2).
