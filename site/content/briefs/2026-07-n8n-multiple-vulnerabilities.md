---
title: Multiple Vulnerabilities in n8n Workflow Automation Platform
slug: 2026-07-n8n-multiple-vulnerabilities
description: An attacker can exploit multiple vulnerabilities in the n8n workflow automation platform to bypass security measures, perform a Denial of Service attack, disclose sensitive information, manipulate files, conduct SQL injection, and execute arbitrary code.
date: "2026-07-23T11:03:21Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - vulnerability
  - rce
  - sql-injection
  - denial-of-service
  - data-exfiltration
  - defense-evasion
vendors:
  - n8n GmbH
products:
  - n8n
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein Angreifer kann mehrere Schwachstellen in n8n ausnutzen
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Sicherheitsvorkehrungen zu umgehen
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: einen Denial of Service Angriff durchzuführen
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Informationen offenzulegen
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: beliebigen Programmcode auszuführen
    confidence_band: med
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2489
---

The German Federal Office for Information Security (BSI) has released an advisory concerning multiple vulnerabilities discovered in n8n, an open-source workflow automation platform. These vulnerabilities, while not individually detailed in the advisory, collectively allow an attacker to bypass security mechanisms, perform Denial of Service attacks, disclose sensitive information, manipulate files, execute SQL injection attacks, and achieve arbitrary code execution. The advisory does not specify if these vulnerabilities are actively being exploited in the wild, but due to the critical nature of remote code execution and data compromise, immediate attention from users of n8n is highly recommended. The scope of impact extends across various environments where n8n is deployed, including Windows, Linux, and cloud-based systems, emphasizing the broad potential for compromise across diverse infrastructure.

## Impact

Successful exploitation of these vulnerabilities in n8n could lead to severe consequences for affected organizations. Attackers could gain unauthorized access to sensitive data stored or processed by n8n workflows, potentially resulting in data exfiltration or compliance breaches. The ability to manipulate files or execute arbitrary code implies a complete compromise of the n8n instance and potentially the underlying system, allowing for further lateral movement or the deployment of additional malicious payloads. Denial of Service attacks could disrupt critical business operations reliant on n8n workflows, leading to financial losses and reputational damage. The advisory from BSI highlights the broad spectrum of risks, from data integrity issues to complete system control, if these flaws are left unaddressed.

## Recommendation

* Organizations using the n8n platform (affected_products: n8n) should apply all available security updates and patches released by n8n GmbH immediately to address the multiple vulnerabilities.
* Monitor n8n application server logs (affected_products: n8n) for any anomalies indicative of attempted exploitation, such as unusual process creations, file modifications, or network connections.
