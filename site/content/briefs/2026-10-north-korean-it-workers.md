---
title: North Korean IT Workers Expanding Facilitator Networks and Coercion Tactics
slug: 2026-10-north-korean-it-workers
description: North Korean state-controlled IT workers are scaling global employment fraud operations by utilizing domestic facilitators, KVM-over-IP hardware, and remote management tools to exfiltrate data and generate revenue.
date: "2026-10-13T23:45:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - insider-threat
  - identity-fraud
  - espionage
  - dprk
  - remote-access
  - social-engineering
  - extortion
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: North Korean ITWs post fake job openings on well-known job boards often as freelance gigs with simple requests such as interviewing on someone's behalf or receiving and hosting laptops in your home.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: ITWs continue to use remote desktop software to connect to employment-related devices. Examples include AnyDesk, TeamViewer, RustDesk, Chrome Remote Desktop, Splashtop Streamer, and remote monitoring and management (RMM) software.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: ITWs use external hardware such as TinyPilot, PiKVM, GL.iNet, and other Keyboard Video Mouse (KVM) over IP devices to control laptops.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078.004
    technique_name: 'Valid Accounts: Cloud Accounts'
    evidence: ITWs pay to use, and apply for employment with, facilitators' social media or professional networking accounts which often contain years of legitimate activity history.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Human Resources
    - Identity and Access Management (IAM)
  immediate_actions:
    - action: Review and audit endpoint software inventories for unauthorized remote control and RMM utilities.
      owner: SOC
      due: 48h
      evidence: FBI identifies AnyDesk, TeamViewer, RustDesk, and Chrome Remote Desktop as commonly abused.
  enrichment_needed:
    - item: Identity verification workflows
      owner: HR
      reason: Need to harden current hiring processes to include live verification to prevent use of stolen PII.
      evidence: Source explicitly recommends live verification and E-Verify.
  hunt_leads:
    - lead: Remote employees with persistent connections from residential ISPs that do not align with employee records.
      technique_id: T1219
      data_needed:
        - VPN connection logs
        - Endpoint EDR location data
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: ITWs utilize laptop farms at residential locations to hide geographic presence.
  mitigation_plan:
    - priority: immediate
      action: Mandate hardware-based MFA for all remote access and corporate resource authentication.
      owner: IAM
      addresses: KVM-over-IP and remote access abuse
      evidence: FBI recommends Identity in Depth to counter evolving ITW tactics.
---

The Democratic People's Republic of Korea (DPRK) continues to deploy thousands of state-controlled IT workers (ITWs) to infiltrate Western organizations. These actors are increasingly leveraging networks of facilitators - both witting and unwitting - to circumvent improved organizational identity verification measures. By utilizing "laptop farms," where employment devices are hosted in residential locations to bypass geolocation controls, ITWs maintain a persistent, obfuscated remote presence. These actors frequently target organizations holding U.S. government contracts or security clearances, seeking high-value access to intellectual property and sensitive personally identifiable information (PII). Recent intelligence indicates a concerning escalation in tactics, with ITWs moving beyond standard fraud to employ physical intimidation, extortion, and threats of violence against former employers and facilitators to ensure revenue extraction. This operation provides approximately 85-90% of the revenue used to support North Korea's military and weapons programs.

## Attack Chain

1. Recruitment of U.S.-based facilitators via freelance job boards or financial hardship targeting.
2. Acquisition of stolen or synthetic PII and verification of credentials through identity verification services.
3. Submission of job applications, often subcontracted to third-party freelancers in South Asia or West Africa to maximize volume.
4. Deployment of KVM-over-IP hardware (e.g., TinyPilot, PiKVM) or separate control laptops to maintain remote access to the employer-provided device.
5. Installation of unauthorized remote management software, including AnyDesk, TeamViewer, RustDesk, or Chrome Remote Desktop, and tools like OBS Studio with VDO.Ninja plugins.
6. Execution of daily work tasks while routing screen recordings through multi-hop remote connections to the ITW's actual location.
7. Exfiltration of sensitive corporate data and PII to maintain compliance with North Korean state oversight requirements.
8. Post-termination extortion using threats of public data disclosure or physical violence to force further payments.

## Impact

Successful infiltration by these actors results in significant national security risks, intellectual property theft, and corporate espionage. Beyond the loss of proprietary data, organizations face reputational damage, the legal and compliance risks associated with identity theft, and physical safety concerns due to the escalation of extortion tactics. The decentralized nature of these operations makes identifying a single point of failure difficult, requiring organizations to adopt an identity-in-depth approach to verify the legitimacy of remote personnel continuously throughout their employment lifecycle.

## Recommendation

Prioritize the implementation of identity-in-depth verification strategies as recommended by the FBI:
- Enforce hardware-based multi-factor authentication (MFA) that cannot be proxied by KVM-over-IP devices.
- Implement continuous, periodic identity re-verification during the employment lifecycle, including live video-based identity checks.
- Monitor for the presence of unauthorized remote access tools such as AnyDesk, TeamViewer, RustDesk, and Splastop, particularly on devices that should not require them for standard job roles.
- Audit network logs for connections originating from unexpected residential IP ranges that do not match the expected work location of the employee.
- Establish a cross-functional response team (HR, Security, IT) to investigate anomalies in employee behavior, such as sudden changes in communication patterns, refusal to appear on camera, or irregularities in account management.
