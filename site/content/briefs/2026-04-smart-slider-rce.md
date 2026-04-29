---
title: Smart Slider 3 Pro Compromised Update Leads to Remote Code Execution
slug: 2026-04-smart-slider-rce
description: Smart Slider 3 Pro version 3.5.1.35 for WordPress and Joomla contains a multi-stage remote access toolkit injected through a compromised update system allowing unauthenticated remote code execution and system takeover.
date: "2026-04-09T23:17:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - wordpress
  - joomla
  - remote-code-execution
  - plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
cves:
  - id: CVE-2026-34424
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34424
rules:
  - title: Detect Smart Slider 3 Pro HTTP Header RCE Attempt
    description: Detects attempts to exploit CVE-2026-34424 by sending malicious HTTP headers to trigger pre-authentication remote shell execution.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1071.001
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Smart Slider 3 Pro Suspicious File Modification
    description: Detects modification of core files or plugin files associated with Smart Slider 3 Pro, indicating a potential compromise.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect Smart Slider 3 Pro Admin Account Creation
    description: Detects creation of new administrator accounts potentially through the compromised plugin.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Smart Slider 3 Pro version 3.5.1.35, a popular WordPress and Joomla plugin, is vulnerable to remote code execution due to a compromised update system. This vulnerability, tracked as CVE-2026-34424, allows unauthenticated attackers to inject a multi-stage remote access toolkit. The attackers leverage this toolkit to execute arbitrary code and commands, effectively taking control of the affected web server. This vulnerability poses a significant threat to websites using the vulnerable plugin, potentially leading to data theft, website defacement, or use of the server for malicious purposes. Defenders should prioritize patching or removing the affected plugin version immediately.

## Attack Chain

1. The attacker compromises the Smart Slider 3 Pro update server.
2. A malicious update is pushed to vulnerable Smart Slider 3 Pro installations (version 3.5.1.35).
3. The plugin downloads and installs the malicious update, injecting the multi-stage remote access toolkit.
4. The attacker triggers pre-authentication remote shell execution by sending crafted HTTP headers to the web server.
5. An authenticated backdoor is established, allowing the attacker to execute arbitrary PHP code or OS commands.
6. The attacker creates hidden administrator accounts within WordPress or Joomla to maintain persistent access.
7. Credentials and access keys are exfiltrated from the compromised system.
8. Persistence is maintained through multiple injection points, including modifications to must-use plugins and core files.

## Impact

Successful exploitation of CVE-2026-34424 leads to complete compromise of the affected web server. Attackers can gain unauthorized access to sensitive data, including user credentials, database information, and proprietary code. Websites can be defaced, injected with malware, or used as part of a botnet. The vulnerability affects all users of Smart Slider 3 Pro version 3.5.1.35, regardless of the underlying operating system. Given the widespread use of WordPress and Joomla, a large number of websites are potentially at risk.

## Recommendation

*   Immediately remove or update Smart Slider 3 Pro to a patched version newer than 3.5.1.35 to remediate CVE-2026-34424.
*   Monitor web server logs for suspicious HTTP requests with unusual headers indicative of attempted pre-authentication shell execution as described in the Attack Chain.
*   Implement the provided Sigma rules to detect suspicious process creation and file modifications related to the injected toolkit.
*   Audit user accounts for unauthorized administrator accounts as the attacker creates hidden accounts.
