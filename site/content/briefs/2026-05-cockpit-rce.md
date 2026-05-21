---
title: Cockpit 359 Remote Code Execution Vulnerability
slug: 2026-05-cockpit-rce
description: Cockpit version 359 is vulnerable to remote code execution, and a public exploit is available on Exploit-DB, increasing the risk for unpatched systems.
date: "2026-05-21T13:31:32Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - rce
  - webapps
  - exploit
products:
  - Cockpit 359
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.exploit-db.com/exploits/52572
rules:
  - title: Detect Cockpit 359 RCE Attempt
    description: Detects potential exploitation attempts of the RCE vulnerability in Cockpit 359 based on suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
  - title: Detect Suspicious Cockpit Process Execution
    description: Detects execution of unusual processes spawned by the Cockpit web server process.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A remote code execution (RCE) vulnerability affects Cockpit version 359. A public exploit (EDB-52572) demonstrating the vulnerability has been published on Exploit-DB. Cockpit is a web-based system administration interface. The existence of a public exploit significantly raises the risk to systems running unpatched instances of Cockpit 359. Attackers can leverage this exploit to execute arbitrary code on the target system, potentially leading to complete system compromise. Defenders should prioritize patching or mitigating this vulnerability.

## Attack Chain

1. Attacker identifies a vulnerable Cockpit 359 instance accessible over the network.
2. Attacker crafts a malicious HTTP request containing the RCE exploit.
3. The malicious request is sent to the vulnerable Cockpit instance.
4. The Cockpit application processes the request, triggering the RCE vulnerability.
5. The attacker executes arbitrary code on the server, such as injecting a web shell.
6. The attacker uses the web shell for further reconnaissance within the compromised network.
7. The attacker escalates privileges to gain administrative access.
8. The attacker deploys malware or exfiltrates sensitive data.

## Impact

Successful exploitation of the RCE vulnerability in Cockpit 359 allows attackers to execute arbitrary code on the affected system. This can lead to complete system compromise, data breaches, and further lateral movement within the network. The availability of a public exploit makes this vulnerability easily exploitable by both sophisticated and unsophisticated threat actors. Organizations using Cockpit 359 are at high risk until they apply the necessary patches or implement mitigation measures.

## Recommendation

*   Deploy the Sigma rule `Detect Cockpit 359 RCE Attempt` to your SIEM to identify potential exploitation attempts.
*   Apply available patches for Cockpit 359 to remediate the RCE vulnerability.
*   Monitor web server logs for suspicious activity targeting Cockpit instances to detect unusual requests.
