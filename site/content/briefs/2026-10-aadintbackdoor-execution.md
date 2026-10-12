---
title: Detection of ConvertTo-AADIntBackdoor PowerShell Cmdlet Execution
slug: 2026-10-aadintbackdoor-execution
description: The execution of the ConvertTo-AADIntBackdoor PowerShell cmdlet indicates an attempt to compromise Azure AD federation settings to enable unauthorized token generation and persistent access.
date: "2026-10-12T18:03:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure-ad
  - persistence
  - privilege-escalation
  - powershell
  - identity-security
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1484.002
    technique_name: 'Domain Trust Modification: Domain Trust Modification'
    evidence: This particular command is designed to create a backdoor in a federated Azure AD domain.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: This analytic detects the execution of the ConvertTo-AADIntBackdoor command via PowerShell Script Block Logging.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_convertto_aadintbackdoor_execution_via_powershell_script.yml
  - https://atomicredteam.io/privilege-escalation/T1484.002/#atomic-test-1---add-federation-to-azure-ad
rules:
  - title: Detect ConvertTo-AADIntBackdoor Execution
    description: Detects the execution of the ConvertTo-AADIntBackdoor cmdlet, often indicative of Azure AD federation tampering.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1484.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all administrative workstations
      owner: SOC
      due: 24h
      evidence: Source requirement for detecting PowerShell-based toolkit execution
  hunt_leads:
    - lead: Search for historical occurrences of 'ConvertTo-AADIntBackdoor' in PowerShell logs
      technique_id: T1484.002
      data_needed:
        - Powershell Script Block Logging 4104
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The cmdlet is highly specific to AADInternals toolkit usage for federation tampering
  mitigation_plan:
    - priority: immediate
      action: Review all Azure AD domain federation settings for unauthorized signing certificates
      owner: IT Operations
      addresses: T1484.002
      evidence: Source identifies federation modification as the primary vector for persistence
---

The ConvertTo-AADIntBackdoor command is a specific functionality within the AADInternals toolkit, often utilized during security assessments but frequently abused by attackers to establish persistence within Azure AD environments. When invoked, this cmdlet modifies the federation settings of a target Azure AD domain. By altering these configurations, the attacker can force the identity provider to accept security tokens that the attacker can craft, effectively bypassing Multi-Factor Authentication (MFA) and impersonating any user within the tenant. This technique provides deep, persistent access to cloud resources and facilitates widespread privilege escalation. Detection of this activity is critical, as it signifies a fundamental compromise of the trust relationship in federated identity environments.

## Attack Chain

1. Attacker gains initial access to a workstation with administrative rights over Azure AD.
2. The AADInternals module is downloaded or imported into a PowerShell session.
3. The attacker authenticates to Azure AD using legitimate credentials or compromised session tokens.
4. The `ConvertTo-AADIntBackdoor` cmdlet is executed via PowerShell to manipulate domain federation settings.
5. The federation configuration is updated to incorporate attacker-controlled signing certificates.
6. The attacker generates forged SAML assertions or security tokens using the modified federation configuration.
7. The attacker presents forged tokens to Azure AD to authenticate as high-privilege users or service principals.
8. Final objective of persistent access and data exfiltration is achieved through impersonated account privileges.

## Impact

Successful execution of this technique allows an attacker to achieve full control over user authentication for the affected Azure AD tenant. This results in the ability to bypass MFA, escalate privileges, and maintain long-term persistence that is often invisible to standard endpoint-based security controls. Such a compromise impacts the entire identity infrastructure, potentially exposing all federated applications and data within the organization's cloud environment.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) across all administrative workstations to ensure the command-line arguments of AADInternals usage are captured.
* Deploy the provided Sigma rule to detect the specific string "ConvertTo-AADIntBackdoor" within script block events.
* Review all modifications to Azure AD domain federation settings through the Azure portal or audit logs to identify unauthorized changes.
* Establish strict Just-In-Time (JIT) access policies for administrative accounts that possess permissions to modify domain federation configurations.
