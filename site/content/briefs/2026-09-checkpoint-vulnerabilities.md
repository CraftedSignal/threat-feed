---
title: Critical Vulnerabilities in Check Point Security Appliances
slug: 2026-09-checkpoint-vulnerabilities
description: Check Point has disclosed critical vulnerabilities, including CVE-2026-85102 and CVE-2026-85103, affecting various Security Gateway, Management Server, and Spark Firewall deployments.
date: "2026-09-10T06:54:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - network-security
  - rce
  - high-confidence-source
vendors:
  - Check Point
products:
  - Security Gateway
  - Spark Firewall
  - Security Management Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2026-85102 enables authentication bypass and remote code execution in Remote Access and Site-to-Site VPN.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2026-85103 - ASN.1 decoding heap overflow leading to a remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-85102
    cvss: 9.8
  - id: CVE-2026-85103
    cvss: 9.8
references:
  - https://support.checkpoint.com/results/sk/sk1000117/
  - https://support.checkpoint.com/results/sk/sk1000118/
  - https://cyber.gc.ca/en/alerts-advisories/check-point-security-advisory-av26-902
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Apply recommended firmware updates for all Check Point Security Gateway, Spark Firewall, and Management Server instances.
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends applying necessary updates.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to VPN and management interfaces to known trusted IP ranges until patches are verified.
      owner: IT Operations
      addresses: CVE-2026-85102
      evidence: Advisory identifies VPN-based authentication bypass vulnerability.
---

On September 9, 2026, Check Point released security advisories identifying multiple critical vulnerabilities across its product line, specifically impacting Security Gateway, Security Management Server, and Spark Firewall appliances. The flaws include CVE-2026-85102, which allows for authentication bypass and remote code execution (RCE) via Site-to-Site or Remote Access VPN configurations, and CVE-2026-85103, a heap overflow vulnerability in ASN.1 decoding that also facilitates RCE. These vulnerabilities present significant risks to enterprise perimeter security, as successful exploitation could grant attackers unauthorized access to internal networks or complete control over the affected appliances. Defenders should prioritize patching and monitor for unusual traffic patterns associated with VPN termination points and ASN.1 processing services.

## Impact

Successful exploitation of these vulnerabilities allows unauthenticated attackers to achieve remote code execution on internet-facing Check Point infrastructure. This impact could lead to full system compromise, exfiltration of sensitive configuration data, lateral movement into protected internal network segments, and long-term persistence within the target organization's security boundary.

## Recommendation

* Apply vendor-supplied security patches or updates for Security Gateway, Security Management Server, and Spark Firewall as documented in the Check Point support articles linked below.
* Monitor firewall and VPN logs for anomalous authentication attempts or unexpected process crashes that may indicate exploitation attempts (CVE-2026-85102, CVE-2026-85103).
* Ensure management interfaces are isolated from the public internet and restricted to authorized management subnets.
