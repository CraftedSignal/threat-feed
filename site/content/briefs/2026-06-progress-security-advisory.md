---
title: Progress Security Advisory (AV26-552) Addressing Multiple Critical Vulnerabilities
slug: 2026-06-progress-security-advisory
description: Progress released critical security advisories between June 2 and 4, 2026, addressing multiple vulnerabilities, including CVE-2026-7312, CVE-2026-7198, CVE-2026-7195, CVE-2026-7201, CVE-2026-7313, CVE-2026-8037, and CVE-2026-33691, in Sitefinity CMS, Sitefinity Insight, and Progress Kemp LoadMaster, which could lead to various impacts if exploited, necessitating immediate patching.
date: "2026-06-14T14:21:34Z"
lastmod: "2026-08-07T21:14:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:progress:sitefinity:*:*:*:*:*:*:*:*
  - cpe:2.3:a:progress:connection_manager_for_objectscale:*:*:*:*:*:*:*:*
  - cpe:2.3:a:progress:ecs_connection_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:o:progress:loadmaster:*:*:*:*:*:*:*:*
  - cpe:2.3:a:owasp:owasp_modsecurity_core_rule_set:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CBFB47A0-CA83-566E-88FB-C2AD0B92470A&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - web-application
  - cms
  - load-balancer
  - patch-management
  - cve
vendors:
  - Progress
products:
  - Sitefinity CMS (multiple versions)
  - Sitefinity Insight (multiple versions)
  - Progress Kemp LoadMaster (GA v7.2.63.1 and prior)
  - Progress Kemp LoadMaster (LTSF v7.2.54.17 and prior)
  - Kemp LoadMaster
  - LoadMaster
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7312
    cvss: 10
    epss: 0.00441
  - id: CVE-2026-7198
    cvss: 9.8
    epss: 0.00443
  - id: CVE-2026-7195
    cvss: 8.8
    epss: 0.00471
  - id: CVE-2026-7201
    cvss: 8.8
    epss: 0.00348
  - id: CVE-2026-7313
    cvss: 8.7
    epss: 0.00319
  - id: CVE-2026-8037
    cvss: 9.6
    epss: 0.84793
  - id: CVE-2026-33691
    cvss: 6.8
    epss: 0.03579
references:
  - https://cyber.gc.ca/en/alerts-advisories/progress-security-advisory-av26-552
  - https://community.progress.com/s/article/Sitefinity-Security-Advisory-for-Addressing-Security-Vulnerabilities-CVE-2026-7312-CVE-2026-7198-CVE-2026-7195-CVE-2026-7201-CVE-2026-7313-May-2026
  - https://community.progress.com/s/article/LoadMaster-Critical-Security-Bulletin-June-2026-CVE-2026-8037-CVE-2026-33691
  - https://www.progress.com/trust-center
  - https://sploitus.com/exploit?id=CBFB47A0-CA83-566E-88FB-C2AD0B92470A&utm_source=rss&utm_medium=rss
  - https://thehackernews.com/2026/07/latest-progress-kemp-loadmaster-pre.html
  - https://www.cisa.gov/news-events/alerts/2026/08/07/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://www.cve.org/CVERecord?id=CVE-2026-8037
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=CBFB47A0-CA83-566E-88FB-C2AD0B92470A
  - type: ip
    value: 192.42.116.58
  - type: ip
    value: 192.42.116.105
  - type: ip
    value: 146.70.139.154
ioc_counts:
  ip: 3
  url: 1
rules:
  - title: Detect Possible Sitefinity CMS Web Exploitation Attempts
    description: Detects suspicious character sequences or commands in HTTP requests targeting Sitefinity CMS, which could indicate attempts to exploit vulnerabilities like CVE-2026-7312, CVE-2026-7198, CVE-2026-7195, CVE-2026-7201, CVE-2026-7313.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1498
    data_sources:
      - webserver
  - title: Detect Web Server Spawning Suspicious Child Process
    description: Detects a web server process (e.g., IIS worker process) spawning suspicious child processes like command shells or scripting interpreters, which can indicate successful exploitation of vulnerabilities (e.g., CVE-2026-7312, CVE-2026-8037 leading to RCE).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Outbound Network Connection from Web Server Process
    description: Detects a web server process initiating outbound network connections to non-standard ports or suspicious destinations, potentially indicating a post-exploitation command and control (C2) channel established after successful exploitation of a vulnerability like CVE-2026-7312 or CVE-2026-8037.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1090
    data_sources:
      - network_connection
      - windows
rules_count: 3
updates:
  - at: "2026-06-30T09:10:16Z"
    level: L2
    summary: poc_available; added CVE-2026-7201
    sources:
      - sploitus
  - at: "2026-07-01T14:28:50Z"
    level: L2
    summary: added CVE-2026-7195
    sources:
      - the-hacker-news
  - at: "2026-08-07T18:47:31Z"
    level: L2
    summary: added CVE-2026-7198 +1
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/alerts/2026/08/07/cisa-adds-one-known-exploited-vulnerability-catalog
  - at: "2026-08-07T21:14:57Z"
    level: L2
    summary: added CVE-2026-7195 +1
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-8037
---

Between June 2 and 4, 2026, Progress Software released urgent security advisories (AV26-552) addressing a range of vulnerabilities across its product line, notably including critical updates for Sitefinity CMS, Sitefinity Insight, and Progress Kemp LoadMaster. These advisories detail several CVEs, specifically CVE-2026-7312, CVE-2026-7198, CVE-2026-7195, CVE-2026-7201, CVE-2026-7313 affecting Sitefinity products, and CVE-2026-8037, CVE-2026-33691 impacting Kemp LoadMaster appliances. The vulnerabilities could allow for unauthorized access, remote code execution, or denial-of-service, posing a significant risk to organizations utilizing these products. Defenders must prioritize the immediate application of patches to prevent potential exploitation by malicious actors seeking to compromise critical web applications and network infrastructure.

## Attack Chain

1.  **Vulnerable System Identification:** An attacker identifies an unpatched Progress Sitefinity CMS, Sitefinity Insight, or Kemp LoadMaster instance exposed to the internet, potentially via automated scanning tools.
2.  **Initial Vulnerability Exploitation:** The attacker crafts and sends a malicious request or payload targeting one of the identified critical vulnerabilities (e.g., CVE-2026-7312 for Sitefinity, CVE-2026-8037 for LoadMaster).
3.  **Remote Code Execution (Hypothetical):** Successful exploitation could lead to remote code execution (RCE), allowing the attacker to execute arbitrary commands on the underlying server, such as spawning a `powershell.exe` or `bash` process.
4.  **Establishing Persistence:** The attacker deploys a web shell (for CMS) or modifies appliance configuration (for LoadMaster) to maintain unauthorized access, creating a backdoor for future access.
5.  **Internal Reconnaissance & Privilege Escalation:** The attacker then performs internal reconnaissance, enumerating system configurations, user accounts, and network topology, seeking to escalate privileges within the compromised environment.
6.  **Lateral Movement & Data Access:** Using gained privileges, the attacker moves laterally across the network to access sensitive data, intellectual property, or other critical systems.
7.  **Impact Execution:** Depending on the attacker's objectives, this could culminate in data exfiltration, deployment of ransomware, or disruption of critical load balancing services.

## Impact

The successful exploitation of these vulnerabilities could lead to severe consequences for affected organizations. For Sitefinity CMS and Insight, compromise could result in unauthorized access to sensitive data, defacement of public-facing web properties, full control over the content management system, or the ability to launch further attacks against visitors. For Kemp LoadMaster, exploitation could allow attackers to bypass security controls, redirect network traffic, disrupt essential load-balancing services, or gain a foothold within the network infrastructure. Ultimately, these vulnerabilities pose a risk of significant data breaches, operational downtime, and reputational damage.

## Recommendation

*   Patch CVE-2026-7312, CVE-2026-7198, CVE-2026-7195, CVE-2026-7201, CVE-2026-7313, CVE-2026-8037, and CVE-2026-33691 on all affected Progress Sitefinity CMS, Sitefinity Insight, and Kemp LoadMaster instances immediately.
*   Enable detailed web server logging for Sitefinity instances (logsource: webserver) to capture unusual HTTP requests targeting known vulnerable paths, and deploy the "Detect Possible Sitefinity CMS Web Exploitation Attempts" Sigma rule.
*   Implement process creation monitoring on Windows systems hosting Sitefinity (logsource: process_creation) and deploy the "Detect Web Server Spawning Suspicious Child Process" Sigma rule to identify post-exploitation activity.
*   Enable network connection logging on web servers (logsource: network_connection) and deploy the "Detect Suspicious Outbound Network Connection from Web Server Process" Sigma rule to detect potential command and control (C2) communications.
