---
title: Progress Software LoadMaster and MOVEit WAF Vulnerabilities Lead to RCE and Root Privileges
slug: 2026-07-progress-software-rce-root
description: Multiple vulnerabilities have been identified in Progress Software LoadMaster and MOVEit WAF products, allowing an attacker from an adjacent network to execute arbitrary program code and gain root privileges on the affected systems.
date: "2026-07-28T10:55:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - progress-software
  - loadmaster
  - moveit
  - waf
  - rce
  - privilege-escalation
  - network-security
vendors:
  - Progress Software
products:
  - LoadMaster
  - MOVEit WAF
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein Angreifer aus einem angrenzenden Netzwerk kann mehrere Schwachstellen in Progress Software LoadMaster und Progress Software MOVEit ausnutzen
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: um beliebigen Programmcode auszuführen
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: und Root-Rechte zu erlangen
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2544
---

Progress Software has disclosed multiple critical vulnerabilities affecting their LoadMaster and MOVEit Web Application Firewall (WAF) products. These flaws enable an attacker, who has established access to an adjacent network segment, to achieve arbitrary code execution and ultimately gain root privileges on the compromised appliance. While specific CVEs and technical details of the vulnerabilities are not yet publicly available in this advisory, the described impact is severe, potentially leading to full system compromise. Organizations utilizing these products should prioritize immediate patching as attackers could leverage this access for data exfiltration, service disruption, or as a pivot point into the broader corporate network. The disclosure by CERT-Bund (BSI) indicates a high level of concern regarding these issues.

## Attack Chain

1. An attacker obtains access to a network segment adjacent to the target Progress Software LoadMaster or MOVEit WAF appliance.
2. The attacker identifies unpatched instances of Progress Software LoadMaster or MOVEit WAF within the adjacent network.
3. The attacker crafts and sends specially designed malicious requests or inputs, exploiting one or more unspecified vulnerabilities present in the affected software.
4. Successful exploitation results in the execution of arbitrary program code within the context of the vulnerable application or service on the appliance.
5. The executed code then leverages further vulnerabilities or misconfigurations to escalate privileges, achieving root access to the underlying operating system of the appliance.
6. With root-level access, the attacker gains full control over the compromised LoadMaster or MOVEit WAF appliance, potentially leading to further network compromise.

## Impact

The successful exploitation of these vulnerabilities allows an attacker to achieve full control over the affected Progress Software LoadMaster and MOVEit WAF appliances by executing arbitrary code with root privileges. This level of compromise enables attackers to potentially manipulate network traffic, bypass security controls, exfiltrate sensitive data, inject malware, or use the appliance as a beachhead for further attacks into the internal network. The specific number of affected organizations is not disclosed, but given the widespread use of LoadMaster and MOVEit WAF for critical network functions, the potential for broad impact is significant.

## Recommendation

* Prioritize updating all Progress Software LoadMaster and MOVEit WAF installations to the latest patched versions as soon as they become available from Progress Software, referencing the products LoadMaster and MOVEit WAF.
* Review network segmentation and access controls to limit adjacency for critical appliances, reducing the attack surface for vulnerabilities requiring adjacent network access.
* Monitor your LoadMaster and MOVEit WAF appliances for unusual process activity, network connections, or unauthorized configuration changes, specifically looking for indicators related to code execution and privilege escalation, as described in the TTPs.
