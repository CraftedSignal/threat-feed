---
title: China-Linked Espionage Campaign Targeting Global Infrastructure via Integrity Technology Group
slug: 2026-10-integrity-technology-espionage
description: Integrity Technology Group, a Chinese for-profit entity, is conducting multi-year cyber espionage targeting government, healthcare, and religious institutions using automated vulnerability scanning, credential harvesting, and specialized data exfiltration tools.
date: "2026-10-08T19:12:19Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Integrity Technology Group
cpes:
  - cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*
  - cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:8.2:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:8.3:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:9.0:*:*:*:*:*:*:*
  - cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*
  - cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:onlyoffice:document_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:strapi:strapi:*:*:*:*:*:*:*:*
tags:
  - espionage
  - china
  - cyber-espionage
  - microsoft-365
  - dcsync
vendors:
  - GNU
  - ProFTPD
  - ISC
  - Apache
  - Pulse Secure
  - GitLab
  - ONLYOFFICE
  - Strapi
  - Microsoft
  - Juniper Networks
  - Jenkins
  - Oracle
products:
  - Bash
  - ProFTPD (< 9.9.7-P2)
  - BIND (< 9.9.7-P2)
  - Struts
  - Connect Secure
  - GitLab
  - Document Server
  - Strapi
  - Exchange Server
  - Microsoft 365
  - ScreenOS
  - Jenkins
  - WebLogic Server
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The hackers look for flaws in networks and web applications with open-source scanners such as Nmap, masscan, and WPScan, the advisory said.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.006
    technique_name: DCSync
    evidence: To take credentials, they ran a tool named DC.exe that uses DCSync, a technique that copies data from a domain controller through Active Directory's replication service.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: They often rename the installer conhost.exe or dllhost.exe so it looks like a Windows file, and they set the client to reconnect each time the machine starts.
    confidence_band: high
cves:
  - id: CVE-2015-3306
    cvss: 10
    epss: 0.96752
  - id: CVE-2015-5477
    epss: 0.91284
  - id: CVE-2019-11510
    cvss: 10
    epss: 0.99999
  - id: CVE-2021-22205
    cvss: 10
    epss: 0.99731
  - id: CVE-2021-3199
    cvss: 9.8
    epss: 0.08215
  - id: CVE-2023-22894
    cvss: 4.9
    epss: 0.01658
iocs:
  - type: domain
    value: dns.studiocloud.xyz
  - type: domain
    value: natcloudservice.com
ioc_counts:
  domain: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - CTI
    - Detection Engineering
  immediate_actions:
    - action: Block listed C2 domains at network perimeter
      owner: SOC
      due: 4h
      evidence: FBI advisory identifies these domains as active C2 infrastructure
  hunt_leads:
    - lead: Identify suspicious outbound traffic to dns.studiocloud.xyz or natcloudservice.com
      technique_id: T1071.001
      data_needed:
        - DNS query logs
        - Proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies these as primary C2 infrastructure
---

Integrity Technology Group, a China-based for-profit company linked to state security agencies, has conducted widespread espionage against government, law enforcement, healthcare, and religious institutions across Southeast Asia, Africa, and North America since at least 2021. The group leverages a diverse set of penetration testing scripts and automated scanning tools to identify and exploit vulnerabilities in legacy services and web applications. Beyond exploitation, they utilize password spraying against Microsoft 365 and Exchange environments, coupled with XSS-based phishing to harvest credentials. 

The group maintains persistence through disguised legitimate software and exfiltrates sensitive email content via custom bots and tools that interface directly with Exchange Web Services. Notably, the group facilitates third-party access to stolen data via a specialized web portal, indicating a high-level operational model that prioritizes data monetization or dissemination. US and UK authorities have sanctioned the group for its role in targeting critical infrastructure. Defenders should prioritize auditing Active Directory replication, monitoring Exchange interface access, and patching the documented vulnerabilities exploited by the group.

## Attack Chain

1. Initial Reconnaissance: Attackers scan for exposed services (ports 21, 22, 53, 80, 443, 1080) using tools like Nmap, masscan, and MicroScan (containing 1,300+ penetration scripts).
2. Initial Access: Attackers exploit known vulnerabilities (CVE-2014-6278, CVE-2015-3306, CVE-2015-5477, CVE-2016-3081, CVE-2019-11510, CVE-2021-22205, CVE-2021-3199, CVE-2023-22894) or perform password spraying against Microsoft 365/Exchange interfaces.
3. Credential Harvesting: Actors deploy XSS payloads on legitimate web pages to redirect users to fake login portals to steal usernames and passwords, or use EBurst to brute-force authentication.
4. Persistence: Attackers install SoftEther VPN, renaming the binary to 'conhost.exe' or 'dllhost.exe' to mimic Windows system processes and establishing persistence upon system reboot.
5. Credential Access: Attackers execute 'DC.exe' to leverage the DCSync technique, extracting account credentials and trust relationships from domain controllers.
6. Collection: Attackers deploy the PHP script 'Curlc4.txt' or the 'office-cli' utility to interface with Exchange Web Services (EWS) and copy sensitive mailboxes.
7. Exfiltration: Stolen email content is compressed and uploaded to attacker-controlled C2 infrastructure, such as 'natcloudservice.com'.
8. Impact: Stolen information is ingested into a web-based portal to provide third-party access to the intelligence, affecting diverse sectors including law enforcement and healthcare.

## Impact

This campaign has resulted in the theft of high-value communications from government agencies, law enforcement, healthcare systems, and religious organizations globally. By enabling third-party access to stolen emails through a web portal, the threat actor significantly increases the potential for downstream exploitation and geopolitical intelligence leverage. The duration of the campaign, active since 2021, suggests large-scale, long-term exposure of sensitive data across multiple continents.

## Recommendation

- Block known malicious C2 domains including 'dns.studiocloud.xyz' and 'natcloudservice.com' at the DNS resolver level.
- Patch the 8 identified vulnerabilities (CVE-2014-6278, CVE-2015-3306, CVE-2015-5477, CVE-2016-3081, CVE-2019-11510, CVE-2021-22205, CVE-2021-3199, CVE-2023-22894) across all perimeter and internal services.
- Enforce MFA across all Microsoft 365, VPN, and critical email infrastructure.
- Audit Active Directory for anomalous replication events associated with the DCSync technique (e.g., unexpected 'GetNCChanges' calls).
- Review web server logs for suspicious MicroScan patterns or XSS injection attempts.
- Monitor process creation for 'conhost.exe' or 'dllhost.exe' originating from non-system paths, specifically those associated with VPN binary signatures.
