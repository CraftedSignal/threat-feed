---
title: 'Kemp LoadMaster and Progress Software MOVEit WAF: Multiple Vulnerabilities'
slug: 2026-05-kemp-moveit-vulns
description: Multiple vulnerabilities in Kemp LoadMaster and Progress Software MOVEit WAF could allow an attacker to execute arbitrary code or circumvent security measures.
date: "2026-05-22T07:25:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - code-execution
  - security-bypass
vendors:
  - Kemp
  - Progress Software
products:
  - LoadMaster
  - MOVEit WAF
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1185
rules:
  - title: Detect Possible MOVEit WAF Security Bypass
    description: Detects possible security bypass attempts in Progress MOVEit WAF based on unusual HTTP requests.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Possible Kemp LoadMaster Code Execution
    description: Detects possible code execution attempts in Kemp LoadMaster based on suspicious web requests.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities have been identified in Kemp LoadMaster and Progress Software MOVEit WAF. An attacker can exploit these vulnerabilities to execute arbitrary program code or bypass existing security measures. These vulnerabilities pose a significant risk to organizations using these products, as successful exploitation could lead to unauthorized access, data breaches, or system compromise. Defenders should apply appropriate patches and mitigations to prevent exploitation. The specific nature and impact of each vulnerability are detailed in vendor advisories.

## Attack Chain

1. The attacker identifies an exploitable vulnerability in Kemp LoadMaster or Progress MOVEit WAF.
2. The attacker crafts a malicious request or payload specifically designed to trigger the vulnerability.
3. The attacker sends the malicious request to the targeted LoadMaster or MOVEit WAF instance.
4. The vulnerable software processes the malicious request, leading to code execution.
5. The attacker gains unauthorized access to the system, potentially escalating privileges.
6. The attacker uses the compromised system to move laterally within the network.
7. The attacker executes further commands to install malware or exfiltrate sensitive data.
8. The attacker achieves their final objective, such as data theft, system disruption, or ransomware deployment.

## Impact

Successful exploitation of these vulnerabilities can lead to a range of damaging consequences. Attackers could gain unauthorized access to sensitive data, disrupt critical business operations, or deploy ransomware, leading to significant financial losses and reputational damage. The number of potential victims is significant, as both Kemp LoadMaster and Progress MOVEit WAF are widely used in various sectors.

## Recommendation

*   Investigate and apply the latest security patches for Kemp LoadMaster to mitigate code execution vulnerabilities (refer to vendor advisories).
*   Investigate and apply the latest security patches for Progress Software MOVEit WAF to prevent security bypass (refer to vendor advisories).
*   Deploy the Sigma rule "Detect Possible MOVEit WAF Security Bypass" to identify potential exploitation attempts (see rule below).
*   Deploy the Sigma rule "Detect Possible Kemp LoadMaster Code Execution" to identify potential exploitation attempts (see rule below).
