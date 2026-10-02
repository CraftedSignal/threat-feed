---
title: Arbitrary Code Execution Vulnerability in Kiteworks Email Protection Gateway
slug: 2026-10-kiteworks-epg-rce
description: An unauthenticated remote code execution vulnerability in Kiteworks Email Protection Gateway (EPG) allows attackers to gain root-level access via input-handling flaws in public endpoints.
date: "2026-10-02T08:12:17Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Kiteworks
products:
  - Email Protection Gateway (EPG)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A combination of input-handling flaws in publicly reachable endpoints of the Kiteworks Email Protection Gateway may potentially allow an unauthenticated remote attacker to achieve arbitrary code execution.
    confidence_band: high
references:
  - https://www.cisecurity.org/advisory/a-vulnerability-in-kiteworks-epg-email-security-gateway-could-allow-for-arbitrary-code-execution_2026-107
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all internet-facing Kiteworks EPG appliances
      owner: IT Operations
      due: 24h
      evidence: Vulnerability exists on publicly reachable endpoints
    - action: Restrict access to Kiteworks EPG management interfaces to authorized IP ranges
      owner: SOC
      due: 24h
      evidence: Unauthenticated remote access enables arbitrary code execution
  enrichment_needed:
    - item: Vulnerable version range
      owner: CTI
      reason: Current report does not specify which versions are exploitable
      evidence: No version data in source
  mitigation_plan:
    - priority: immediate
      action: Contact Kiteworks support for current patches
      owner: IT Operations
      addresses: Email Protection Gateway
      evidence: Security advisory recommends vendor engagement
---

A vulnerability has been identified in the Kiteworks Email Protection Gateway (EPG) that allows an unauthenticated remote attacker to achieve arbitrary code execution. The EPG platform, used for email encryption, decryption, and policy enforcement, contains input-handling flaws within its publicly accessible web endpoints. By exploiting these flaws, an attacker can execute arbitrary commands with root privileges on the underlying appliance. This represents a significant security risk for organizations using Kiteworks as a perimeter email security solution, as the appliance typically handles sensitive inbound and outbound communications. Successful exploitation leads to a complete system compromise, enabling attackers to intercept, read, or modify enterprise emails or pivot further into the internal network.

## Impact

Successful exploitation of this vulnerability results in full administrative control over the targeted Email Protection Gateway. As the appliance is positioned at the network edge to manage encrypted email traffic, unauthorized root access allows for the total compromise of email data, potential credential theft, and sustained persistence within the organization's communication infrastructure. The number of potentially affected victims includes any enterprise relying on Kiteworks EPG for email security.

## Recommendation

Prioritize monitoring of all public-facing Kiteworks EPG instances for anomalous requests originating from untrusted external IPs. Since no specific patch version or CVE identifier was provided in the initial security advisory, contact Kiteworks support immediately to confirm if your specific deployment version is affected and request the relevant security update or mitigation configuration.
