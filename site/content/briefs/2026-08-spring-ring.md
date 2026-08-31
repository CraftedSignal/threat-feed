---
title: Spring Ring Voice Phishing Campaign Targeting Microsoft Teams
slug: 2026-08-spring-ring
description: The Spring Ring campaign is a coordinated voice phishing operation impersonating IT help desk staff via Microsoft Teams to coerce victims into executing remote access tools or facilitating NTLM relay attacks against domain controllers.
date: "2026-08-31T11:54:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - social-engineering
  - identity
  - teams
  - vishing
vendors:
  - Microsoft
products:
  - Microsoft Teams
  - Quick Assist
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The Spring Ring campaign leverages Microsoft Teams and voice phishing to deploy malware.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers coerce victims into executing... custom PowerShell-based remote access Trojans.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
iocs:
  - type: domain
    value: InternalSystemsDaily.onmicrosoft.com
  - type: domain
    value: ITProtectionDepartment.onmicrosoft.com
  - type: domain
    value: MandatoryNetworkMonitoring.onmicrosoft.com
  - type: domain
    value: InternalUSAHelpDeskIT.onmicrosoft.com
  - type: domain
    value: CertifiedUpdateNetwork.onmicrosoft.com
  - type: domain
    value: infrastructureopsdesk.onmicrosoft.com
  - type: domain
    value: systemdeploymentcenter.onmicrosoft.com
  - type: domain
    value: systemsupportoperations.onmicrosoft.com
ioc_counts:
  domain: 8
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block listed .onmicrosoft.com attacker domains at the perimeter and Teams gateway
      owner: SOC
      due: 24h
      evidence: IOC list provided in the brief
  mitigation_plan:
    - priority: immediate
      action: Tighten Microsoft Teams external communication policies
      owner: IT Operations
      addresses: Initial Access vector
      evidence: Unit 42 research recommendation
---

The Spring Ring campaign, active between January and April 2026, represents an evolution in social engineering by integrating voice phishing (vishing) directly into the Microsoft Teams workflow. By exploiting the "Chat with Anyone" feature, attackers establish external connections with enterprise users while impersonating internal IT help desk personnel. These actors utilize professional, urgency-focused display names and provision Microsoft 365 tenants with .onmicrosoft.com subdomains to mirror legitimate corporate infrastructure. 

Once contact is established through Teams chat, the attackers initiate audio calls to manipulate victims into executing unauthorized RMM tools or custom PowerShell-based remote access Trojans (RATs). Beyond initial access, the campaign demonstrates advanced post-exploitation capabilities, including the use of tools like PetitPotam to perform NTLM relay attacks against target domain controllers. With 150 employees targeted across at least 10 companies, this campaign highlights the shift toward using trusted collaboration platforms as a primary vector for identity-based attacks.

## Attack Chain

1. Attackers establish an external Microsoft 365 tenant using a deceptive name (e.g., ITProtectionDepartment.onmicrosoft.com).
2. Attackers initiate a Microsoft Teams chat with a target, masquerading as an internal IT help desk member.
3. Attackers place a voice call to the target via the Microsoft Teams platform to build trust and pressure the victim.
4. The attacker manipulates the victim into executing a payload, such as a malicious PowerShell script or an RMM utility (e.g., Quick Assist).
5. The execution of the malicious script bypasses AMSI and provides the attacker with remote access to the victim workstation.
6. Attackers use the compromised host to perform internal network reconnaissance.
7. Attackers utilize NTLM relay tools (e.g., PetitPotam) to force authentication from a Domain Controller toward attacker-controlled infrastructure.
8. Final objective is achieved, resulting in unauthorized access or privilege escalation within the target domain.

## Impact

The Spring Ring campaign targeted at least 10 major organizations, impacting over 150 employees. Successful exploitation allows for complete workstation compromise, remote control, and the potential for domain-level privilege escalation via NTLM relay attacks against Domain Controllers.

## Recommendation

- Enable Microsoft Teams "External Access" policies to block communication from untrusted domains or specific .onmicrosoft.com tenants not explicitly allowlisted.
- Monitor for anomalous process creation events associated with common RMM utilities (e.g., Quick Assist, TeamViewer) when launched by non-IT personnel.
- Implement and enforce strict SMB signing and LDAP signing to mitigate NTLM relay attacks such as those utilizing PetitPotam.
- Deploy detections for suspicious PowerShell patterns, specifically those attempting to disable AMSI or initiate unauthorized network connections.
- Educate end-users on identifying and reporting "Chat with Anyone" requests from external users claiming to be internal IT support.
