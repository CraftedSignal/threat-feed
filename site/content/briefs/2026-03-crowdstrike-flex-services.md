---
title: CrowdStrike Flex for Services Expands Access to Incident Response Expertise
slug: 2026-03-crowdstrike-flex-services
description: CrowdStrike is expanding its Falcon Flex model to its services offering, providing flexible access to incident response, proactive security services, advisory, platform services, and training.
date: "2026-03-28T08:17:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - incident-response
  - security-services
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-extends-the-falcon-flex-model-to-services/
rules:
  - title: Detect PowerShell Downgrade Attack
    description: Detects PowerShell being invoked with a version parameter to downgrade it.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Execution from Suspicious Folder
    description: Detects execution of a binary from folders commonly used to store downloads or temporary files.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is extending the Falcon Flex model to its services offering to provide organizations with the flexibility and speed required to prepare for modern threats. This model provides flexible consumption of expert-led cybersecurity services. The Zero Dollar Flex Fund provides proactive services hours to strengthen incident readiness. Customers draw down from a standalone services entitlement that can be applied across the services portfolio based on priorities and operational needs. This includes incident response, proactive security services, advisory, platform services, and training, allowing for adaptable consumption of expertise as priorities shift.

## Attack Chain

This brief focuses on incident response readiness and service procurement, rather than a specific attack chain. The described service aims to improve an organization's ability to respond to a variety of attacks.

1.  **Initial Compromise:** (This step is hypothetical but included for context) An attacker gains initial access to a target network via phishing, exploiting a vulnerability, or other means.
2.  **Detection:** The organization detects suspicious activity on its network, possibly through existing security tools.
3.  **Engagement of CrowdStrike Services:** The organization utilizes CrowdStrike Flex for Services to engage incident response experts. This step involves drawing down from the pre-arranged services entitlement.
4.  **Incident Response:** CrowdStrike's experts begin investigating the incident, identifying the scope of the breach, and containing the threat.
5.  **Remediation:** CrowdStrike assists with remediation efforts, which may include patching systems, removing malware, and restoring data.
6.  **Proactive Services:** After the incident, the organization uses the remaining Flex for Services hours for proactive security assessments, vulnerability management, and training to improve future defenses.
7. **Ongoing Monitoring and Improvement:** The organization uses the lessons learned from the incident and proactive services to continuously improve its security posture.

## Impact

A successful attack, without adequate incident response readiness, can lead to data breaches, financial losses, reputational damage, and disruption of business operations. The CrowdStrike Flex for Services aims to mitigate these impacts by providing rapid access to expert support, reducing the time it takes to respond to incidents, and improving overall security preparedness. This model enables organizations to align services consumption with actual security requirements, particularly beneficial for organizations needing expert support before broader platform commitments.

## Recommendation

*   Evaluate CrowdStrike Flex for Services to improve incident response readiness and access expert support (all sections).
*   If eligible, explore the Zero Dollar Flex Fund for initial access to CrowdStrike Services (all sections).
*   Use proactive service hours to assess readiness, improve defenses, and strengthen operational preparedness (Attack Chain, Step 6).
