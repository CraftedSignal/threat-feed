---
title: KnowledgeDeliver ViewState Deserialization Vulnerability Exploitation
slug: 2026-05-knowledgedeliver-viewstate-deserialization
description: An unauthenticated remote code execution vulnerability, CVE-2026-5426, in Digital Knowledge's KnowledgeDeliver LMS platform due to shared ASP.NET machine keys allows attackers to inject malicious code, ultimately leading to Cobalt Strike infection of user workstations.
date: "2026-05-25T05:10:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - knowledgedeliver
  - viewstate-deserialization
  - rce
  - web-shell
  - cobalt-strike
  - cve-2026-5426
vendors:
  - Digital Knowledge
products:
  - KnowledgeDeliver
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Local Account
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5426
    cvss: 7.5
    epss: 0.00071
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/knowledgedeliver-viewstate-deserialization-vulnerability/
  - https://www.cve.org/CVERecord?id=CVE-2026-5426
  - https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0009.md
rules:
  - title: Detect KnowledgeDeliver BLUEBEAM Webshell Deployment
    description: Detects potential deployment of BLUEBEAM webshell (Godzilla) by monitoring process creation events from w3wp.exe with suspicious command line arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1505.003
    data_sources:
      - process_creation
      - windows
  - title: Detect KnowledgeDeliver ICACLS Permission Changes
    description: Detects potential privilege escalation through ICACLS command to grant Everyone full access to web application directory.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

In late 2025, Mandiant investigated a security incident involving a compromised KnowledgeDeliver web server. KnowledgeDeliver, a Learning Management System (LMS) by Digital Knowledge, was found to be vulnerable to unauthenticated Remote Code Execution (RCE) due to the use of identical pre-shared ASP.NET machine keys across multiple customer deployments before February 24, 2026. This vulnerability, tracked as CVE-2026-5426, allowed an unknown threat actor to inject malicious code into the LMS platform. The attacker's goal was to compromise users visiting the site through web shell deployment, file tampering, and eventual Cobalt Strike BEACON infection of user workstations. This highlights the critical importance of maintaining unique and secure machine keys for ASP.NET applications.

## Attack Chain

1.  The attacker identifies a KnowledgeDeliver instance with default ASP.NET machine keys.
2.  The attacker crafts a malicious ViewState payload, exploiting CVE-2026-5426, by deserializing arbitrary objects.
3.  The attacker sends the crafted ViewState payload within the `__VIEWSTATE` parameter in an HTTP POST request to the vulnerable KnowledgeDeliver server.
4.  The server deserializes the malicious ViewState, leading to code execution within the `w3wp.exe` process.
5.  The attacker deploys the BLUEBEAM (.NET-based Godzilla) in-memory web shell within the `w3wp.exe` process for persistence and command execution.
6.  The attacker uses the `icacls` command to grant "Everyone" full access to the web application directory, escalating privileges.
7.  The attacker modifies a JavaScript file to display a fake security alert, prompting users to install a malicious "security authentication plugin".
8.  The modified JavaScript silently loads a remote malicious script hosted on an attacker-controlled domain, ultimately leading to Cobalt Strike BEACON infection of user workstations.

## Impact

Successful exploitation of CVE-2026-5426 allows an attacker to achieve unauthenticated remote code execution on KnowledgeDeliver servers. This can lead to the deployment of web shells, file tampering, and the infection of user workstations with malware such as Cobalt Strike. The modified JavaScript file displays a fake security alert, which tricks users into installing a malicious "security authentication plugin", leading to further compromise. This incident underscores the critical risk posed by shared machine keys in ASP.NET applications.

## Recommendation

*   Monitor Windows Application logs for Event ID 1316 from the `ASP.NET 4.0.30319.0` source related to ViewState verification failures, as described in the overview, especially event codes 4009.
*   Monitor for unusual child processes spawned by `w3wp.exe` (IIS worker process), such as `cmd.exe`, `whoami`, and `powershell.exe`, as mentioned in the "Suspicious Process Activity" section.
*   Implement file integrity monitoring for `.js`, `.aspx`, and `.config` files within the web root to detect unauthorized modifications, including the addition of remote script loaders, as described in the "File Integrity Monitoring" section.
*   Deploy the Sigma rule "Detect KnowledgeDeliver BLUEBEAM Webshell Deployment" to detect post-exploitation activity related to web shell deployment.
