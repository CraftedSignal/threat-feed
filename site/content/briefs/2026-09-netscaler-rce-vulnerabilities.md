---
title: Remote Code Execution Vulnerabilities in NetScaler ADC and Gateway
slug: 2026-09-netscaler-rce-vulnerabilities
description: Multiple vulnerabilities discovered in NetScaler ADC and NetScaler Gateway may allow an unauthenticated remote attacker to execute arbitrary commands, potentially leading to full appliance compromise.
date: "2026-09-28T22:19:15Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Cloud Software Group
products:
  - NetScaler ADC
  - NetScaler Gateway
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The most severe of these vulnerabilities could allow for remote code execution of commands on the system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Successful exploitation of the most severe of these vulnerabilities could allow for remote code execution of commands on the system.
    confidence_band: high
references:
  - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-netscaler-adc-and-netscaler-gateway-could-allow-for-remote-code-execution_2026-103
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all internet-facing NetScaler ADC and Gateway instances.
      owner: IT Operations
      due: 24h
      evidence: NetScaler ADC and NetScaler Gateway are identified as the vulnerable products.
  enrichment_needed:
    - item: Specific CVE IDs and patch versions.
      owner: CTI
      reason: Necessary for identifying vulnerable software versions and applying specific remediation.
      evidence: Source provides general advisory without CVEs.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor patches as soon as they are published by Cloud Software Group.
      owner: IT Operations
      addresses: RCE vulnerabilities in NetScaler products
      evidence: Advisory notes these vulnerabilities could allow for remote code execution.
---

Multiple vulnerabilities have been identified within NetScaler ADC and NetScaler Gateway products, developed by Cloud Software Group. These appliances are widely deployed for application delivery optimization and secure remote access. The most significant of these flaws permits an unauthenticated remote attacker to achieve remote code execution (RCE) on the underlying system. Successful exploitation allows for the execution of arbitrary commands, granting the attacker control over the appliance. Given the role these devices play in network security and remote access, compromise provides a critical beachhead for deeper lateral movement and interception of encrypted traffic or user credentials. Defenders should prioritize auditing internet-facing NetScaler instances and preparing for rapid deployment of vendor-supplied patches as they become available.

## Impact

Successful exploitation of these vulnerabilities leads to full system compromise of the NetScaler ADC or Gateway appliance. This could result in unauthorized access to sensitive application data, interception of user traffic, potential exfiltration of authentication tokens, and the ability to pivot into protected internal segments of the network. The scope affects all organizations utilizing these products for load balancing and secure remote access.

## Recommendation

- Identify all internet-facing NetScaler ADC and NetScaler Gateway instances within the infrastructure.
- Monitor logs for unusual outbound connections or unexpected process execution originating from the NetScaler management interface.
- Apply security patches immediately once released by Cloud Software Group.
- Restrict access to the NetScaler management interface to trusted, internal IP ranges to reduce the attack surface for remote exploitation attempts.
