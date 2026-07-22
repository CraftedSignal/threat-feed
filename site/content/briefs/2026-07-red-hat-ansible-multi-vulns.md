---
title: Multiple Vulnerabilities in Red Hat Ansible Automation Platform
slug: 2026-07-red-hat-ansible-multi-vulns
description: Multiple vulnerabilities exist in Red Hat Ansible Automation Platform, stemming from issues in components such as node-tar, linkify-it, protobufjs, brace-expansion, fast-uri, and DOMPurify. A remote, unauthenticated attacker can exploit these flaws to bypass security measures, perform Cross-Site Scripting (XSS) attacks, manipulate data, trigger Denial-of-Service (DoS) conditions, or execute arbitrary code on the affected system.
date: "2026-07-22T10:07:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - xss
  - denial-of-service
  - data-manipulation
  - vulnerability
  - ansible
  - red-hat
vendors:
  - Red Hat
products:
  - Ansible Automation Platform
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1211
    technique_name: Exploitation for Defense Evasion
    evidence: Sicherheitsmaßnahmen zu umgehen
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Cross-Site-Scripting-Angriffe durchzuführen
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: beliebigen Code auszuführen
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Defacement
    evidence: Daten zu manipulieren
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
    evidence: einen Denial-of-Service-Zustand auszulösen
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2452
---

Red Hat Ansible Automation Platform is affected by multiple high-severity vulnerabilities residing in several integrated third-party components, specifically `node-tar`, `linkify-it`, `protobufjs`, `brace-expansion`, `fast-uri`, and `DOMPurify`. These flaws enable a remote, anonymous attacker to compromise the platform's integrity and availability. Attackers can leverage these weaknesses to bypass existing security controls, inject and execute malicious client-side scripts via Cross-Site Scripting (XSS), manipulate critical data within the platform, trigger Denial-of-Service (DoS) conditions causing system unavailability, or achieve arbitrary code execution on the underlying server. While specific CVEs were not detailed in the advisory, the aggregation of these vulnerabilities presents a significant risk to organizations utilizing the affected platform, potentially leading to full system compromise or disruption of automation workflows.

## Attack Chain

1. A remote, anonymous attacker identifies a publicly accessible Red Hat Ansible Automation Platform instance.
2. The attacker identifies or scans for the presence of the known vulnerabilities in third-party components like `node-tar`, `linkify-it`, `protobufjs`, `brace-expansion`, `fast-uri`, or `DOMPurify` within the platform.
3. The attacker crafts a malicious input or request specifically designed to exploit one of the identified flaws, such as a specially malformed data structure, a crafted URI, or an XSS payload.
4. The crafted payload is sent to the vulnerable Ansible Automation Platform instance, targeting the specific component or endpoint susceptible to the identified vulnerability.
5. The malicious input successfully bypasses existing security measures, such as input validation or sanitization, which are intended to protect against such attack vectors.
6. The exploited vulnerability leads to one or more of the specified adverse effects: Cross-Site Scripting (XSS), data manipulation, Denial-of-Service (DoS), or arbitrary code execution.
7. The attacker achieves their objective, which could range from stealing credentials via XSS, corrupting system data, causing service disruption, or establishing a persistent backdoor through arbitrary code execution.

## Impact

The successful exploitation of these vulnerabilities can lead to significant and varied consequences. Attackers can gain the ability to bypass security measures, execute malicious scripts in user browsers (XSS), manipulate sensitive data, or render the Ansible Automation Platform inaccessible through Denial-ofService attacks. The most severe impact involves arbitrary code execution, which could grant the attacker full control over the affected system, allowing for data exfiltration, further lateral movement within the network, or the deployment of additional malicious payloads. The lack of specific CVEs suggests a broad risk across multiple attack surfaces within the platform's dependency stack.

## Recommendation

* Apply vendor security updates to Red Hat Ansible Automation Platform immediately to patch the identified vulnerabilities.
* Monitor for unusual HTTP requests targeting Ansible Automation Platform instances, especially those containing malformed data, URI structures, or common XSS payloads, which could indicate exploitation attempts.
* Enable comprehensive logging on Red Hat Ansible Automation Platform and underlying operating systems to detect anomalous process creation, unexpected network connections, or unauthorized file modifications.
