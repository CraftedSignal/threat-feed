---
brief_id: brief-2026-10-30-ad-cs-teams-impersonation
event_id: brief-2026-10-30-ad-cs-teams-impersonation
revision: 1
activity_at: "2026-10-30T21:17:08Z"
title: Microsoft Teams help desk impersonation and AD CS abuse
slug: 2026-10-ad-cs-teams-impersonation
description: Threat actors are leveraging Microsoft Teams to impersonate support personnel, socially engineering users into granting remote access via Quick Assist to deploy portable runtimes and conduct AD CS abuse (ESC1 and ESC8).
date: "2026-10-30T21:17:08Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
vendors:
  - Microsoft
products:
  - Active Directory Certificate Services
  - Microsoft Teams
  - Quick Assist
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: Both incidents began with Teams phishing messages and calls that impersonated support personnel.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: The social engineering persuaded a user to establish an attacker-controlled remote session, primarily by guiding the user to open Quick Assist.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: The payload then performed host and network discovery and began assessing AD CS.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Case 1, the threat actor abused an Enterprise CA Security Configuration 1 (ESC1) -vulnerable certificate template to obtain authentication certificates for privileged accounts.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review AD CS template configurations against ESC1 and ESC8 guidance.
      owner: IT Operations
      due: 48h
      evidence: AD CS can turn a certificate request into a durable authentication path.
  hunt_leads:
    - lead: Hunt for portable runtime execution (Python, Bun, Java) originating from user profile directories.
      technique_id: T1059.006
      data_needed:
        - Process creation logs (Event ID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Commands launched during the session created a KB-prefixed staging directory under the user profile, extracted the archive... and started the included payload.
  mitigation_plan:
    - priority: immediate
      action: Enable Extended Protection for Authentication on AD CS Web Enrollment servers.
      owner: IT Operations
      addresses: ESC8 NTLM relay
      evidence: An attacker relays a user or machine account NTLM authentication to an AD CS web enrollment endpoint that lacks relay protections.
---

Microsoft observed intrusions where actors used Microsoft Teams to impersonate IT support, gaining interactive access via tools like Quick Assist. Following initial access, actors staged portable runtimes (Python, Bun, Java) in user-writable directories to facilitate host discovery and Active Directory Certificate Services (AD CS) exploitation. Confirmed abuse paths include ESC1 (certificate template misconfiguration) and ESC8 (NTLM relay to AD CS Web Enrollment), the latter involving PetitPotam to coerce authentication.

## Attack Chain
1. Initial Access: Threat actors use Microsoft Teams to impersonate IT support via messages and calls.
2. Execution: The user is socially engineered into initiating a remote support session via Quick Assist.
3. Staging: Attackers place a compressed archive into the user's Downloads folder and extract payloads into a 'KB-' prefixed directory under the user profile.
4. Runtime Execution: Payloads are executed using portable runtimes (Python, Bun, Java) launched from user-writable locations.
5. Discovery: The actor performs internal host and network discovery and evaluates AD CS environments.
6. Escalation: Actors perform certificate abuse via ESC1 (template manipulation) or ESC8 (NTLM relay via PetitPotam) to obtain privileged identity certificates.
7. Persistence/Exfiltration: Obtained certificates are used for PKINIT or DCSync attacks to further compromise the environment.

## Impact
Successful exploitation allows attackers to obtain authentication certificates for privileged identities. These certificates provide durable access independent of user passwords and bypass traditional password reset or workstation re-imaging remediation efforts.

## Recommendation
- Audit AD CS certificate templates for ESC1-vulnerable settings (requester-supplied SAN, broad enrollment).
- Implement NTLM relay protections on AD CS Web Enrollment endpoints (e.g., Extended Protection for Authentication).
- Monitor for unusual processes executing from user profile directories (e.g., Python, Java, Bun).
- Configure alerts for atypical AD CS certificate enrollment activity and the use of PetitPotam-related techniques.
- Disable or restrict the use of Quick Assist for users who do not require it for their roles.
- Ensure all service identities and devices are included in automated incident containment policies to prevent exclusion-based persistence.
