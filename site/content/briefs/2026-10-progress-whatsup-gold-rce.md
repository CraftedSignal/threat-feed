---
brief_id: brief-2026-10-29-progress-whatsup-gold-rce
event_id: brief-2026-10-29-progress-whatsup-gold-rce
revision: 1
activity_at: "2026-10-29T12:27:00Z"
title: 'Progress WhatsUp Gold: Unauthenticated Remote Code Execution (CVE-2024-4883)'
slug: 2026-10-progress-whatsup-gold-rce
description: Progress WhatsUp Gold is vulnerable to unauthenticated remote code execution via a write-what-where primitive in the WriteDataFile service, allowing attackers to plant webshells on the target system.
date: "2026-10-29T12:27:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
cpes:
  - cpe:2.3:a:progress:whatsup_gold:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - webshell
  - vulnerability
vendors:
  - Progress
products:
  - WhatsUp Gold (< 23.1.3)
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated RCE in Progress WhatsUp Gold WriteDataFile service via write-what-where primitive.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Using write what where primitive, to plant C:\\Program Files (x86)\\Ipswitch\\WhatsUp\\html\\NmConsole\\eb8e455a-28d2-4628-80cb-ef2d786c8409.aspx
    confidence_band: high
cves:
  - id: CVE-2024-4883
    cvss: 9.8
    epss: 0.64535
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SINSINOLOGY-CVE-2024-4883
  - https://summoning.team/blog/progress-whatsup-gold-WriteDataFile-CVE-2024-4883-RCE/
  - https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-June-2024
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SINSINOLOGY-CVE-2024-4883&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all servers running Progress WhatsUp Gold and verify versions.
      owner: IT Operations
      due: 24h
      evidence: CVE-2024-4883 affects all versions < 23.1.3.
  hunt_leads:
    - lead: Search webserver logs for requests to .aspx files within the NmConsole directory that are not part of the standard installation baseline.
      technique_id: T1190
      data_needed:
        - Webserver access logs (IIS)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit plants an ASPX webshell at /NmConsole/ on the target server.
  mitigation_plan:
    - priority: immediate
      action: Upgrade WhatsUp Gold to version 23.1.3 or later.
      owner: IT Operations
      addresses: CVE-2024-4883
      evidence: https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-June-2024
---

CVE-2024-4883 is a critical vulnerability in Progress WhatsUp Gold that enables unauthenticated remote code execution. The flaw exists within the ICoreServices component's WriteDataFile service, which contains a write-what-where primitive. Exploitation allows an unauthenticated attacker to plant arbitrary files, such as ASPX webshells, into the application's web directory, leading to full system compromise. The vulnerability affects all versions of WhatsUp Gold prior to 23.1.3. A functional proof-of-concept exploit is publicly available.

## Attack Chain
1. The attacker establishes a network connection to the ICoreServices service on the target's net.tcp port (typically 9643).
2. The attacker interacts with the WriteDataFile service.
3. The attacker leverages the write-what-where primitive to overwrite or create a file in a chosen destination.
4. The attacker targets the web directory of the WhatsUp Gold installation (e.g., C:\Program Files (x86)\Ipswitch\WhatsUp\html\NmConsole\).
5. The attacker plants a malicious ASPX webshell via the primitive.
6. The attacker navigates to the uploaded webshell via a web browser to achieve remote code execution on the underlying server.

## Impact
Successful exploitation grants an unauthenticated attacker full system control, including the ability to execute arbitrary code, modify or exfiltrate data, and maintain persistent access to the server. The vulnerability carries a CVSS 3.1 base score of 9.8.

## Recommendation
- Patch immediately by upgrading all Progress WhatsUp Gold instances to version 23.1.3 or later.
- Review the official Progress security bulletin for additional guidance: https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-June-2024.
- Audit the 'html\NmConsole' directory and its subdirectories for any unexpected .aspx files.
