---
title: 'Red Hat Quay: Multiple Vulnerabilities'
slug: 2026-07-red-hat-quay-vulnerabilities
description: Multiple vulnerabilities in Red Hat Quay allow a remote, authenticated attacker to execute arbitrary code and perform Server-Side Request Forgery (SSRF) attacks.
date: "2026-07-16T10:10:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability-exploitation
  - rce
  - ssrf
  - network
vendors:
  - Red Hat
products:
  - Red Hat Quay
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Ein entfernter, authentisierter Angreifer kann mehrere Schwachstellen in Red Hat Quay ausnutzen, um beliebigen Programmcode auszuführen
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Arbitrary code execution could be used to establish persistence
    confidence_band: med
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Scanning
    evidence: serverseitige Request-Forgery-Angriffe durchzuführen (to perform Server-Side Request Forgery attacks)
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1856
---

Red Hat Quay, a highly scalable and secure container registry, is affected by multiple vulnerabilities that could be exploited by a remote, authenticated attacker. These vulnerabilities enable arbitrary code execution (RCE) and Server-Side Request Forgery (SSRF) attacks. An attacker who has already gained authenticated access to a Red Hat Quay instance can leverage these flaws to compromise the server and potentially access internal network resources. The arbitrary code execution could lead to full control over the Quay environment, allowing for data tampering, theft, or further lateral movement. SSRF vulnerabilities could be abused to probe internal networks, access sensitive services, or bypass network segmentation. This poses a significant risk to organizations using Red Hat Quay for container image management, as a compromised registry could impact the entire software supply chain.

## Attack Chain

1. An attacker gains authenticated access to a Red Hat Quay instance, likely through stolen credentials or by exploiting another vulnerability (e.g., weak authentication).
2. The authenticated attacker identifies and exploits a vulnerability within Red Hat Quay that permits the execution of arbitrary code on the underlying server.
3. Malicious code or commands are injected and executed, potentially establishing a foothold or modifying Quay's behavior.
4. The attacker identifies and exploits a separate or co-occurring Server-Side Request Forgery (SSRF) vulnerability.
5. Using the SSRF vulnerability, the attacker crafts specially malformed requests to trick the Quay server into making requests to internal network endpoints.
6. These internal requests allow the attacker to discover internal services, access administrative interfaces, or retrieve sensitive data from systems not directly exposed to the internet.
7. The attacker uses the executed arbitrary code or the information gained from SSRF to establish persistence within the Quay environment or pivot to other internal systems.
8. The final objective is to achieve full compromise of the Red Hat Quay instance, exfiltrate sensitive data, or use the registry as a platform for further attacks within the organization's network.

## Impact

Successful exploitation of these vulnerabilities by an authenticated attacker can lead to significant impact. Arbitrary code execution grants the attacker full control over the Red Hat Quay instance, potentially allowing for the manipulation or deletion of container images, injection of malicious code into container workflows, or complete system compromise. SSRF attacks enable an attacker to bypass network segmentation, scan internal networks for other vulnerable services, and access sensitive internal resources, leading to data exfiltration or further lateral movement within the compromised network. The compromise of a container registry can have far-reaching effects on software development and deployment pipelines, potentially impacting the integrity and security of applications across the enterprise.

## Recommendation

* Apply available security patches and updates from Red Hat immediately to all Red Hat Quay instances to address these multiple vulnerabilities.
* Implement strong authentication mechanisms and ensure all accounts accessing Red Hat Quay use strong, unique passwords and multi-factor authentication to prevent initial authenticated access.
* Monitor Red Hat Quay logs (e.g., webserver access logs, application logs) for unusual authenticated activity, including repeated failed login attempts, suspicious API calls, or unexpected outbound connections that could indicate SSRF attempts.
* Perform regular vulnerability scanning and penetration testing on Red Hat Quay instances to identify and remediate similar vulnerabilities proactively.
