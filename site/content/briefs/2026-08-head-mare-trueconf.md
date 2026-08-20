---
title: Head Mare APT Exploiting TrueConf Server Vulnerabilities to Deploy PhantomCore and PhantomGraph
slug: 2026-08-head-mare-trueconf
description: The Head Mare APT group is exploiting a chain of vulnerabilities in TrueConf Server to achieve remote code execution as SYSTEM and distribute backdoored installer packages to victims.
date: "2026-08-11T17:45:55Z"
lastmod: "2026-08-20T19:12:07Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Head Mare
cpes:
  - cpe:2.3:a:trueconf:trueconf_server:*:*:*:*:*:windows:*:*
  - cpe:2.3:a:trueconf:trueconf_server:*:*:*:*:*:linux_kernel:*:*
vendors:
  - TrueConf
products:
  - TrueConf Server
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attackers connect to the TrueConf server without prior authorization via port 4307/TCP.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: 'To automatically launch the malware after the system boots, a registry key is created: HKEY_CURRENT_USER\Software\Classes\CLSID\{0340F119-A598-4ed9-B0AC-6F6A12D3E755}\InprocServer32.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The attackers used an account on Microsoft OneDrive cloud storage as their command-and-control (C2) server.
    confidence_band: high
cves:
  - id: CVE-2026-72529
    cvss: 9.8
  - id: CVE-2026-72530
    cvss: 9
references:
  - https://securelist.com/tr/head-mare-targets-trueconf-server-with-phantomcore/120988/
  - https://trueconf.com/blog/update/trueconf-server-security-updates-june-2026
  - https://www.cisa.gov/news-events/alerts/2026/08/20/cisa-adds-two-known-exploited-vulnerabilities-catalog
rules:
  - title: Detect Suspicious PHP Web Shell Creation in TrueConf
    description: Detects the creation or modification of the 'locale.php' file within the TrueConf web directory, indicative of web shell placement.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch TrueConf Server to 5.3.9, 5.4.9, or 5.5.5.
      owner: IT Operations
      due: 24h
      evidence: The vulnerabilities exploited by the attackers were patched by the vendor in the latest TrueConf Server updates.
  hunt_leads:
    - lead: Identify unauthorized file modifications in TrueConf web directory.
      technique_id: T1505.003
      data_needed:
        - File integrity monitoring or EDR file creation events.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers replace the file ...\public\js\locale.php with a web shell.
  mitigation_plan:
    - priority: immediate
      action: Enforce code signing validation for all software updates.
      owner: IT Operations
      addresses: Supply chain attack vectors.
      evidence: The malicious distributions we detected do not have a valid digital signature.
updates:
  - at: "2026-08-20T19:12:07Z"
    level: L2
    summary: added CVE-2026-72529 +1
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/alerts/2026/08/20/cisa-adds-two-known-exploited-vulnerabilities-catalog
---

Since July 2026, the Head Mare APT group has been observed exploiting a chain of vulnerabilities in TrueConf Server (versions 5.3.x, 5.4.x, and 5.5.x) to compromise enterprise conferencing infrastructure. The attackers leverage unauthorized access via TCP port 4307 to trigger remote code execution within an isolated environment, subsequently escalating privileges to NT AUTHORITY\SYSTEM. Once local system access is achieved, the threat actors deploy a PHP web shell ('locale.php') to maintain persistence, conduct infrastructure reconnaissance, and perform supply chain attacks by replacing legitimate TrueConf client installers with versions containing the PhantomCore backdoor. The group further deploys a modular backdoor, PhantomGraph, which uses Microsoft OneDrive for command-and-control communications and establishes persistence through malicious Windows services and registry modifications. This campaign targets critical infrastructure sectors, including energy, manufacturing, and IT, across Russia.

## Attack Chain

1. Attackers establish unauthorized connection to the target TrueConf server via TCP port 4307.
2. Attackers transmit and execute a malicious script on the server by exploiting vulnerability KLCERT-26-057.
3. Attackers exploit vulnerability KLCERT-26-058 to escape the isolated execution environment and gain arbitrary code execution.
4. Execution occurs in the context of the NT AUTHORITY\SYSTEM account on the Windows host.
5. Attackers overwrite the '...\public\js\locale.php' file with a web shell to maintain persistent remote access.
6. The web shell is used to perform internal reconnaissance and gain administrative access to the TrueConf database.
7. Attackers inject the PhantomCore backdoor into legitimate TrueConf client installation files.
8. Attackers deploy PhantomGraph modules ('SysExcSvc.dll' and 'SysReadSvc.dll') via PowerShell as Windows services, utilizing OneDrive for C2.

## Impact

Successful exploitation allows for full system compromise, data exfiltration from conferencing databases, and supply chain attacks against participants who download backdoored client software. Observed targeting includes critical industries such as energy, transportation, and software development, impacting the integrity of internal communications and potentially providing a pivot point into the broader corporate network.

## Recommendation

1. Upgrade all TrueConf Server instances to versions 5.3.9, 5.4.9, or 5.5.5 immediately to remediate the vulnerabilities.
2. Verify the digital signature of all TrueConf client installer files against the official vendor authenticity guidelines to ensure they have not been tampered with.
3. Deploy detection for the creation of non-standard PHP files in the TrueConf installation directory, specifically monitoring for modifications to 'locale.php'.
4. Enable EDR telemetry on all servers hosting TrueConf applications to monitor for unauthorized PowerShell execution and the registration of new Windows services.
