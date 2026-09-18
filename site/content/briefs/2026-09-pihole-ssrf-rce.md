---
title: Pi-hole SSRF to RCE Vulnerability via CVE-2024-34361
slug: 2026-09-pihole-ssrf-rce
description: Pi-hole versions 5.18.2 and earlier are vulnerable to an authenticated SSRF attack via improper URL validation, which can be chained with the Gopherus protocol to achieve remote code execution on the host system.
date: "2026-09-18T10:27:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pi-hole:pi-hole:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - ssrf
vendors:
  - Pi-hole
products:
  - Pi-hole (<= 5.18.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability occurs due to improper URL validation and can be exploited via the authenticated admin login endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The SSRF can be elevated to RCE using the Gopherus protocol to execute arbitrary commands.
    confidence_band: high
cves:
  - id: CVE-2024-34361
    cvss: 8.5
    epss: 0.02828
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-T0X1CX-CVE-2024-34361-PI-HOLE-SSRF-TO-RCE
rules:
  - title: Detect CVE-2024-34361 Exploitation Attempt via Gopherus Protocol
    description: Detects potential SSRF attempts targeting the Pi-hole login endpoint using the Gopherus protocol signature in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all Pi-hole installations to version 5.18.3 or higher.
      owner: IT Operations
      due: 24h
      evidence: CVE-2024-34361 advisory states the vulnerability is addressed in 5.18.3.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Pi-hole admin interface to trusted IPs.
      owner: Security Operations
      addresses: CVE-2024-34361
      evidence: Exploit requires authenticated access to the admin login endpoint.
---

CVE-2024-34361 is a security vulnerability in the Pi-hole DNS sinkhole software affecting versions 5.18.2 and earlier. The flaw stems from improper validation of URL inputs, specifically within the authenticated admin login endpoint. An attacker who has gained low-level authenticated access to the Pi-hole administration interface can leverage this input validation weakness to trigger a Server-Side Request Forgery (SSRF). By manipulating the request body, an attacker can coerce the application to send requests to arbitrary internal services. 

Technical analysis indicates that this SSRF can be escalated to full Remote Code Execution (RCE) through the use of the Gopherus protocol, which allows the crafting of payloads for various services. Successful exploitation grants the attacker the ability to execute arbitrary commands on the underlying host, leading to a complete compromise of system integrity and availability. The availability of public exploit proof-of-concept (PoC) code significantly increases the risk of exploitation for organizations currently running unpatched instances of Pi-hole.

## Attack Chain

1. Attacker obtains low-level credentials to access the Pi-hole web-based administration interface.
2. Attacker navigates to the 'admin/login.php' endpoint and establishes an authenticated session.
3. Attacker identifies a vulnerable input parameter in the request body that fails to properly sanitize URLs.
4. Attacker crafts a malicious request payload incorporating the Gopherus protocol syntax to target internal services or local binaries.
5. The Pi-hole server processes the malicious URL, triggering an outbound SSRF request to the specified target.
6. The SSRF payload exploits the target service or local system component to execute system-level commands.
7. Attacker achieves remote code execution, granting persistent access or the ability to perform further post-exploitation actions on the host.

## Impact

Successful exploitation of CVE-2024-34361 results in full remote code execution on the server hosting the Pi-hole instance. This allows attackers to exfiltrate sensitive network configurations, pivot to other internal network segments, or disrupt DNS resolution services provided by the sinkhole. Given the common deployment of Pi-hole as a central network-wide DNS filtering mechanism, compromise of this host represents a significant threat to internal visibility and security controls.

## Recommendation

1. Immediately upgrade all instances of Pi-hole to version 5.18.3 or later to mitigate CVE-2024-34361.
2. Restrict access to the Pi-hole administration interface to trusted management networks only, preventing unauthorized authentication that acts as a prerequisite for this exploit.
3. Deploy web application firewall (WAF) rules to inspect and filter suspicious traffic containing protocol handlers like 'gopher://' or anomalous URI query parameters targeting 'admin/login.php'.
4. Implement network segmentation to isolate DNS infrastructure from critical internal service segments to limit the blast radius of a potential SSRF-based pivot.
