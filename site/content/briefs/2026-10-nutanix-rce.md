---
title: Arbitrary Code Execution Vulnerability in Nutanix AOS and Prism Central
slug: 2026-10-nutanix-rce
description: A vulnerability in Nutanix AOS and Nutanix Prism Central allows a remote, unauthenticated attacker to bypass security controls and execute arbitrary code with administrative privileges.
date: "2026-10-16T16:27:59Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Nutanix
products:
  - AOS
  - Prism Central
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Nutanix AOS und Nutanix Prism Central ausnutzen, um Sicherheitsvorkehrungen zu umgehen.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Schwachstelle ermöglicht Ausführen von beliebigem Programmcode mit Administratorrechten.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Schwachstelle ermöglicht Ausführen von beliebigem Programmcode mit Administratorrechten.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3991
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review exposure of Nutanix Prism Central instances and restrict access to management interfaces.
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated remote access vulnerability identified in management platform.
  mitigation_plan:
    - priority: immediate
      action: Apply the latest security updates provided by Nutanix for AOS and Prism Central once available.
      owner: IT Operations
      addresses: Arbitrary code execution vulnerability
      evidence: Vendor advisory requires patching to resolve the vulnerability.
---

Nutanix has disclosed a critical security vulnerability affecting Nutanix AOS and Nutanix Prism Central that enables unauthenticated remote attackers to achieve arbitrary code execution with administrative privileges. By exploiting this flaw, an attacker can bypass existing security controls to gain full control over the affected infrastructure components. This vulnerability represents a significant risk to the confidentiality, integrity, and availability of managed environments. Organizations utilizing Nutanix AOS or Prism Central are urged to evaluate their exposure and apply security patches or mitigations provided by the vendor immediately to prevent unauthorized access and potential system compromise.

## Impact

Successful exploitation of this vulnerability grants an attacker administrative-level access to Nutanix AOS or Prism Central environments. This allows for full compromise of the affected virtualization management infrastructure, potentially resulting in data exfiltration, lateral movement within the data center, and the disruption of critical business services managed by the Nutanix platform.

## Recommendation

* Monitor vendor security channels for the release of security patches addressing this flaw in Nutanix AOS and Prism Central.
* Implement network segmentation to restrict access to Prism Central management interfaces to known, authorized administrative hosts only.
* Audit logs for unauthorized access attempts or suspicious management traffic targeting the AOS and Prism Central control planes.
