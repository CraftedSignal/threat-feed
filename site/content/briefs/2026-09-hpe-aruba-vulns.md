---
title: Multiple Critical Vulnerabilities in HPE Aruba Networking Products
slug: 2026-09-hpe-aruba-vulns
description: HPE has disclosed a wide range of vulnerabilities across AOS-CX and Fabric Composer, including RCE, privilege escalation, and DoS flaws, impacting numerous versions of the network operating system.
date: "2026-09-02T18:02:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - networking
  - infrastructure
vendors:
  - HPE
products:
  - AOS-CX (10.13.x < 10.13.1190)
  - AOS-CX (10.16.x < 10.16.1060)
  - AOS-CX (10.17.x < 10.17.1030)
  - AOS-CX (10.18.x < 10.18.1002)
  - AOS-CX (< 10.10.1181)
  - Fabric Composer (< 7.3.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, une élévation de privilèges et un déni de service à distance.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, une élévation de privilèges et un déni de service à distance.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance.
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1104/
  - https://csaf.arubanetworking.hpe.com/2026/hpe_networking_-_hpesbnw05133.txt
  - https://csaf.arubanetworking.hpe.com/2026/hpe_networking_-_hpesbnw05134.txt
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all Aruba AOS-CX and Fabric Composer devices.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies vulnerable product lines.
  mitigation_plan:
    - priority: immediate
      action: Upgrade AOS-CX to latest stable releases and Fabric Composer to 7.3.4 or later.
      owner: IT Operations
      addresses: All listed CVEs
      evidence: Vendor bulletins HPESBNW05133 and HPESBNW05134.
---

On September 1, 2026, HPE Aruba Networking published two security bulletins (HPESBNW05133 and HPESBNW05134) detailing a large volume of vulnerabilities affecting the AOS-CX network operating system and Fabric Composer. These vulnerabilities encompass a broad spectrum of impact, including remote code execution (RCE), privilege escalation, denial of service (DoS), SQL injection (SQLi), cross-site scripting (XSS), server-side request forgery (SSRF), and cross-site request forgery (CSRF). 

The scope of the affected software is significant, covering multiple major release trains of AOS-CX, including versions 10.13.x, 10.16.x, 10.17.x, 10.18.x, and legacy 10.10.x. Fabric Composer versions earlier than 7.3.4 are also impacted. Given the critical nature of these services within enterprise network infrastructure, these vulnerabilities present a high risk for unauthorized network control and data exfiltration. Defenders must verify the current firmware versions of all deployed Aruba switches and controllers against the patched versions identified in the vendor bulletins.

## Impact

Successful exploitation of these vulnerabilities can lead to a complete compromise of the underlying networking equipment. An attacker could potentially bypass security policies, exfiltrate sensitive data passing through the network, or disrupt business operations via denial-of-service attacks. The broad range of vulnerability types (SQLi, XSS, SSRF) implies that internal web interfaces and management APIs are significant vectors. Given the position of Aruba switches at the edge and core of corporate networks, these flaws pose a systemic risk to enterprise network integrity.

## Recommendation

1. Inventory all Aruba AOS-CX and Fabric Composer appliances across the environment.
2. Prioritize patching devices running the legacy AOS-CX 10.10.x train, as these systems have reached end-of-maintenance and are receiving critical-only updates.
3. Apply the security patches provided in HPE bulletins HPESBNW05133 and HPESBNW05134 immediately.
4. Restrict access to management interfaces (HTTPS/SSH/API) to trusted administrative subnets only.
5. Enable robust logging on management interfaces to detect abnormal access patterns or unexpected HTTP/API requests consistent with web injection attempts.
